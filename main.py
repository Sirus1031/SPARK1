# For local testing:
# 1. Install MySQL and create a database/user:
#    CREATE DATABASE door_db;
#    CREATE USER 'testuser'@'localhost' IDENTIFIED BY 'testpass';
#    GRANT ALL PRIVILEGES ON door_db.* TO 'testuser'@'localhost';
# 2. Set SQLALCHEMY_DATABASE_URI to:
#    "mysql+pymysql://testuser:testpass@localhost:3306/door_db"
# 3. Run /dev/init_db once to initialize tables.

"""
app.py -- Dash + Flask admin portal with:
 - Azure AD login (MSAL)
 - MySQL (SQLAlchemy)
 - REST API for Raspberry Pi that validates API key and returns JWT
 - Admin UI to manage cards, access attributes/time windows, view logs

IMPORTANT:
 - Run behind HTTPS in production (Ngrok/dev only for local testing).
 - Store secrets in environment variables or a secrets manager.
 - Use a proper device onboarding flow for API keys (not included).
"""

import os
from urllib.parse import quote_plus
import json
import hashlib
import datetime
from functools import wraps

from flask import Flask, session, redirect, url_for, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
import msal
import jwt  # PyJWT
from werkzeug.security import generate_password_hash, check_password_hash

import dash
from dash import html, dcc, Dash, Input, Output, State, ctx, dash_table
import pandas as pd


# load required secrets (fail fast instead of using insecure defaults)
# load required secrets (with defaults for testing)
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.environ.get("AZURE_TENANT_ID", "common")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-jwt-secret-change-in-production")

DB_USER = os.environ.get("MYSQL_USER", "admin_spark")
DB_PASS = quote_plus(os.environ.get("MYSQL_PASSWORD", "Spark1ETS"))  # quote special chars
DB_HOST = os.environ.get("MYSQL_HOST", "mysql-spark.mysql.database.azure.com")
DB_NAME = os.environ.get("MYSQL_DATABASE", "myconnector")
SQLALCHEMY_DATABASE_URI = os.environ.get(
    "SQLALCHEMY_DATABASE_URI",
    f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:3306/{DB_NAME}?ssl_ca=&ssl_verify_cert=true&ssl_verify_identity=true"
)

PI_TOKEN_EXP_MIN = int(os.environ.get("PI_TOKEN_EXP_MIN", "60"))
FRONTEND_BASE = os.environ.get("FRONTEND_BASE", "https://example.com")

AUTHORITY = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
SCOPE = ["User.Read"]
REDIRECT_PATH = "/getAToken"
REDIRECT_URI = FRONTEND_BASE + REDIRECT_PATH

# -----------------------
# Flask + DB + MSAL Setup
# -----------------------
server = Flask(__name__)
server.config["SECRET_KEY"] = SECRET_KEY
server.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
server.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False



import pymysql, os; 
try:
    conn = pymysql.connect(
        host=os.getenv("MYSQL_HOST", "mysql-spark.mysql.database.azure.com"),
        user=os.getenv("MYSQL_USER", "admin_spark"),
        password=os.getenv("MYSQL_PASSWORD", "Spark1ETS"),
        database=os.getenv("MYSQL_DATABASE", "myconnector"),  # Fixed from MYCONNECTOR
        port=int(os.getenv("MYSQL_PORT", "3306")),
        ssl={'ssl_mode': 'REQUIRED'},  # Added SSL requirement
        connect_timeout=3
    )
    print(f"✅ Connected to MySQL at {os.getenv('MYSQL_HOST', 'mysql-spark.mysql.database.azure.com')}")
    conn.close()
except Exception as e:
    print(f"❌ Could not connect to MySQL: {e}")

db = SQLAlchemy(server)

# -----------------------
# Database Models
# -----------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    oid = db.Column(db.String(128), unique=True)  # Azure object id
    email = db.Column(db.String(256), unique=True)
    name = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)

class Card(db.Model):
    __tablename__ = "cards"
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.String(128), unique=True, nullable=False)  # e.g. RFID tag
    owner = db.Column(db.String(256))
    active = db.Column(db.Boolean, default=True)

class AccessRule(db.Model):
    __tablename__ = "access_rules"
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.String(128), db.ForeignKey("cards.card_id"), nullable=False)
    access_from = db.Column(db.Time, nullable=True)  # daily start time
    access_to = db.Column(db.Time, nullable=True)    # daily end time
    attributes = db.Column(db.Text)  # JSON string for attributes (e.g., doors, roles)

class AccessLog(db.Model):
    __tablename__ = "access_logs"
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.String(128))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    result = db.Column(db.String(64))  # e.g., "granted", "denied", "invalid_card"
    reason = db.Column(db.Text)

class PiDevice(db.Model):
    __tablename__ = "pi_devices"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(128), unique=True)
    api_key_hash = db.Column(db.String(256))  # hashed API key for device
    description = db.Column(db.String(256))
    enabled = db.Column(db.Boolean, default=True)

# -----------------------
# Utility: create MSAL app
# -----------------------
def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        AZURE_CLIENT_ID, authority=authority or AUTHORITY,
        client_credential=AZURE_CLIENT_SECRET, token_cache=cache
    )

def _build_auth_url(scopes=None, state=None):
    msal_app = _build_msal_app()
    return msal_app.get_authorization_request_url(
        scopes or [],
        state=state or None,
        redirect_uri=REDIRECT_URI
    )

# -----------------------
# Flask Routes - Login
# -----------------------
@server.route("/login")
def login():
    session.clear()
    auth_url = _build_auth_url(scopes=SCOPE, state=None)
    return redirect(auth_url)

@server.route(REDIRECT_PATH)
def authorized():
    # Handles redirect from Azure AD
    code = request.args.get("code")
    if not code:
        return "No code provided by Azure", 400
    msal_app = _build_msal_app()
    result = msal_app.acquire_token_by_authorization_code(
        code,
        scopes=SCOPE,
        redirect_uri=REDIRECT_URI
    )
    if "error" in result:
        return f"Login failure: {result.get('error_description')}", 400

    # Store user info in session
    id_token_claims = result.get("id_token_claims")
    if not id_token_claims:
        return "No ID token claims", 400

    oid = id_token_claims.get("oid")
    preferred_username = id_token_claims.get("preferred_username") or id_token_claims.get("upn")
    name = id_token_claims.get("name") or preferred_username

    session["user"] = {
        "oid": oid,
        "email": preferred_username,
        "name": name
    }

    # ensure user exists in DB
    user = User.query.filter_by(oid=oid).first()
    if not user:
        # first time user -> not admin by default. Manually promote via DB or add logic.
        user = User(oid=oid, email=preferred_username, name=name, is_admin=False)
        db.session.add(user)
        db.session.commit()

    return redirect("/")

@server.route("/logout")
def logout():
    session.clear()
    return redirect(
        AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + FRONTEND_BASE
    )

# -----------------------
# Helper: require_login decorator
# -----------------------
def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        usr = session.get("user")
        if not usr:
            return redirect("/login")
        db_user = User.query.filter_by(oid=usr.get("oid")).first()
        if not db_user or not db_user.is_admin:
            return "Forbidden: Admins only", 403
        return f(*args, **kwargs)
    return decorated

# -----------------------
# REST API for Raspberry Pi (device validation)
#
# Flow:
# 1) Pi authenticates with an API key (device-specific). Calls /api/pi/validate to get JWT token.
# 2) Pi uses JWT token on subsequent /api/pi/check_access or to send logs.
# -----------------------
def verify_device_api_key(device_id, api_key_plain):
    device = PiDevice.query.filter_by(device_id=device_id, enabled=True).first()
    if not device:
        return False
    # Compare hashed key
    return check_password_hash(device.api_key_hash, api_key_plain)

@server.route("/api/pi/validate", methods=["POST"])
def pi_validate():
    """
    POST payload: { "device_id": "...", "api_key": "..." }
    -> returns {"token": "<jwt>", "expires_at": "<iso>"}
    """
    data = request.json or {}
    device_id = data.get("device_id")
    api_key = data.get("api_key")
    if not device_id or not api_key:
        return jsonify({"error": "device_id and api_key required"}), 400

    if not verify_device_api_key(device_id, api_key):
        return jsonify({"error": "invalid_device_or_key"}), 401

    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(minutes=PI_TOKEN_EXP_MIN)
    payload = {
        "sub": device_id,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "type": "pi_device"
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token, "expires_at": exp.isoformat()})

def require_pi_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing_token"}), 401
        token = auth.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token_expired"}), 401
        except Exception as e:
            return jsonify({"error": "invalid_token", "detail": str(e)}), 401
        # attach device id to request context
        request.device_id = payload.get("sub")
        return f(*args, **kwargs)
    return decorated

@server.route("/api/pi/check_access", methods=["POST"])
@require_pi_jwt
def pi_check_access():
    """
    Pi posts { "card_id": "..." } with Authorization: Bearer <jwt>
    Server checks rules and returns granted/denied. Also logs access.
    """
    data = request.json or {}
    card_id = data.get("card_id")
    device_id = getattr(request, "device_id", "unknown")
    if not card_id:
        return jsonify({"error": "card_id required"}), 400

    card = Card.query.filter_by(card_id=card_id, active=True).first()
    now = datetime.datetime.utcnow()
    granted = False
    reason = "card_inactive_or_missing"
    if not card:
        reason = "invalid_card"
    else:
        # get rules
        rules = AccessRule.query.filter_by(card_id=card_id).all()
        if not rules:
            # default deny if no rules
            granted = False
            reason = "no_rules"
        else:
            # check if any rule allows now
            for r in rules:
                if r.access_from and r.access_to:
                    # compare only time-of-day
                    tnow = now.time()
                    if r.access_from <= tnow <= r.access_to:
                        granted = True
                        reason = "time_allowed"
                        break
                else:
                    # no time limits => allow
                    granted = True
                    reason = "allowed_no_time_limit"
                    break

    # log
    log = AccessLog(card_id=card_id, timestamp=now, result="granted" if granted else "denied", reason=reason)
    db.session.add(log)
    db.session.commit()

    return jsonify({"granted": granted, "reason": reason})

# Endpoint for Pi to send logs (optionally)
@server.route("/api/pi/send_log", methods=["POST"])
@require_pi_jwt
def pi_send_log():
    payload = request.json or {}
    card_id = payload.get("card_id")
    result = payload.get("result", "unknown")
    reason = payload.get("reason", "")
    log = AccessLog(card_id=card_id, timestamp=datetime.datetime.utcnow(), result=result, reason=reason)
    db.session.add(log)
    db.session.commit()
    return jsonify({"ok": True})

# -----------------------
# Admin REST endpoints used by the Dash UI (server-protected)
# -----------------------
@server.route("/api/admin/cards", methods=["GET", "POST", "DELETE"])
@require_admin
def admin_cards():
    if request.method == "GET":
        cards = Card.query.all()
        return jsonify([{"card_id": c.card_id, "owner": c.owner, "active": c.active} for c in cards])
    if request.method == "POST":
        data = request.json or {}
        card_id = data.get("card_id")
        owner = data.get("owner")
        if not card_id:
            return jsonify({"error": "card_id required"}), 400
        if Card.query.filter_by(card_id=card_id).first():
            return jsonify({"error": "card_exists"}), 400
        c = Card(card_id=card_id, owner=owner)
        db.session.add(c)
        db.session.commit()
        return jsonify({"ok": True})
    if request.method == "DELETE":
        data = request.json or {}
        card_id = data.get("card_id")
        c = Card.query.filter_by(card_id=card_id).first()
        if not c:
            return jsonify({"error": "not_found"}), 404
        db.session.delete(c)
        db.session.commit()
        return jsonify({"ok": True})

@server.route("/api/admin/access_rule", methods=["POST", "DELETE"])
@require_admin
def admin_access_rule():
    if request.method == "POST":
        data = request.json or {}
        card_id = data.get("card_id")
        access_from = data.get("access_from")  # "HH:MM"
        access_to = data.get("access_to")      # "HH:MM"
        attributes = data.get("attributes", {})
        if not card_id:
            return jsonify({"error": "card_id required"}), 400
        # convert times
        atime_from = None
        atime_to = None
        if access_from:
            atime_from = datetime.datetime.strptime(access_from, "%H:%M").time()
        if access_to:
            atime_to = datetime.datetime.strptime(access_to, "%H:%M").time()
        ar = AccessRule(card_id=card_id, access_from=atime_from, access_to=atime_to, attributes=json.dumps(attributes))
        db.session.add(ar)
        db.session.commit()
        return jsonify({"ok": True})
    if request.method == "DELETE":
        data = request.json or {}
        rule_id = data.get("rule_id")
        r = AccessRule.query.filter_by(id=rule_id).first()
        if not r:
            return jsonify({"error": "not_found"}), 404
        db.session.delete(r)
        db.session.commit()
        return jsonify({"ok": True})

@server.route("/api/admin/logs", methods=["GET"])
@require_admin
def admin_logs():
    # simple filters
    card_id = request.args.get("card_id")
    limit = min(int(request.args.get("limit", "200")), 2000)
    query = AccessLog.query
    if card_id:
        query = query.filter_by(card_id=card_id)
    logs = query.order_by(AccessLog.timestamp.desc()).limit(limit).all()
    return jsonify([{"card_id": l.card_id, "timestamp": l.timestamp.isoformat(), "result": l.result, "reason": l.reason} for l in logs])

# -----------------------
# Dash App (UI)
# -----------------------
app = Dash(__name__, server=server, url_base_pathname="/", suppress_callback_exceptions=True)

# Simple top layout: header with login/logout, sections to manage cards, rules, logs
app.layout = html.Div([
    html.Div(id="header", children=[
        html.H2("Door Access Admin Portal"),
        html.Div(id="user-info"),
        html.A("Login (Azure)", href="/login", id="login-link"),
        html.A("Logout", href="/logout", id="logout-link", style={"marginRight": "10px"})
    ], style={"display": "flex", "alignItems": "center", "gap": "10px"}),

    dcc.Tabs(id="tabs", children=[
        dcc.Tab(label="Cards", value="cards"),
        dcc.Tab(label="Access Rules", value="rules"),
        dcc.Tab(label="Logs", value="logs"),
        dcc.Tab(label="Pi Devices (Admin)", value="pi")
    ], value="cards"),
    html.Div(id="tab-content")
])

# -----------------------
# Callbacks: populate header + tab content (server-side fetch)
# -----------------------
@app.callback(
    Output("user-info", "children"),
    [Input("tabs", "value")]
)
def update_user_info(_):
    usr = session.get("user")
    if not usr:
        return html.Span("Not signed in")
    db_user = User.query.filter_by(oid=usr.get("oid")).first()
    name = usr.get("name") or usr.get("email")
    admin_tag = " (admin)" if db_user and db_user.is_admin else ""
    return html.Span(f"Signed in as {name}{admin_tag}")

@app.callback(Output("tab-content", "children"), [Input("tabs", "value")])
def render_tab(tab):
    if tab == "cards":
        # cards management
        cards = Card.query.all()
        df = pd.DataFrame([{"card_id": c.card_id, "owner": c.owner, "active": c.active} for c in cards])
        return html.Div([
            html.H3("Cards"),
            dash_table.DataTable(
                id="cards-table",
                columns=[{"name": c, "id": c} for c in df.columns],
                data=df.to_dict("records"),
                row_selectable="single",
            ),
            html.Div([
                dcc.Input(id="new-card-id", placeholder="card id (tag)", type="text"),
                dcc.Input(id="new-card-owner", placeholder="owner", type="text"),
                html.Button("Add Card", id="add-card-btn")
            ]),
            html.Button("Delete Selected Card", id="delete-card-btn"),
            html.Div(id="cards-msg")
        ])
    if tab == "rules":
        rules = AccessRule.query.all()
        df = pd.DataFrame([{
            "id": r.id,
            "card_id": r.card_id,
            "access_from": r.access_from.isoformat() if r.access_from else "",
            "access_to": r.access_to.isoformat() if r.access_to else "",
            "attributes": r.attributes
        } for r in rules])
        return html.Div([
            html.H3("Access Rules"),
            dash_table.DataTable(
                id="rules-table",
                columns=[{"name": c, "id": c} for c in df.columns],
                data=df.to_dict("records"),
                row_selectable="single",
            ),
            html.Div([
                dcc.Input(id="rule-card-id", placeholder="card id", type="text"),
                dcc.Input(id="rule-from", placeholder="HH:MM", type="text"),
                dcc.Input(id="rule-to", placeholder="HH:MM", type="text"),
                dcc.Input(id="rule-attrs", placeholder='attributes JSON', type="text"),
                html.Button("Add Rule", id="add-rule-btn")
            ]),
            html.Button("Delete Selected Rule", id="delete-rule-btn"),
            html.Div(id="rules-msg")
        ])
    if tab == "logs":
        logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(200).all()
        df = pd.DataFrame([{"card_id": l.card_id, "timestamp": l.timestamp.isoformat(), "result": l.result, "reason": l.reason} for l in logs])
        return html.Div([
            html.H3("Access Logs"),
            dash_table.DataTable(
                id="logs-table",
                columns=[{"name": c, "id": c} for c in df.columns],
                data=df.to_dict("records"),
                page_size=20
            ),
            html.Button("Refresh", id="refresh-logs")
        ])
    if tab == "pi":
        devices = PiDevice.query.all()
        df = pd.DataFrame([{"device_id": d.device_id, "description": d.description, "enabled": d.enabled} for d in devices])
        return html.Div([
            html.H3("Raspberry Pi Devices"),
            dash_table.DataTable(
                id="pi-table",
                columns=[{"name": c, "id": c} for c in df.columns],
                data=df.to_dict("records"),
                row_selectable="single"
            ),
            html.Div([
                dcc.Input(id="new-pi-id", placeholder="device id", type="text"),
                dcc.Input(id="new-pi-desc", placeholder="description", type="text"),
                dcc.Input(id="new-pi-api-key", placeholder="api key (plaintext)", type="text"),
                html.Button("Add Pi Device", id="add-pi-btn")
            ]),
            html.Button("Toggle Selected Device Enabled", id="toggle-pi-btn"),
            html.Div(id="pi-msg")
        ])

# -----------------------
# Callbacks: Add/Delete card and rules (client -> server)
# -----------------------
@app.callback(
    Output("cards-msg", "children"),
    [Input("add-card-btn", "n_clicks"), Input("delete-card-btn", "n_clicks")],
    [State("new-card-id", "value"), State("new-card-owner", "value"), State("cards-table", "selected_rows"), State("cards-table", "data")]
)
def handle_cards(add_click, delete_click, new_card_id, new_card_owner, selected_rows, table_data):
    triggered = ctx.triggered_id
    if triggered == "add-card-btn":
        if not new_card_id:
            return "card_id required"
        # server call
        res = server.test_client().post("/api/admin/cards", json={"card_id": new_card_id, "owner": new_card_owner})
        if res.status_code == 200:
            return "Card added"
        else:
            return f"Error: {res.get_json()}"
    if triggered == "delete-card-btn":
        if not selected_rows:
            return "Select a row first"
        row = table_data[selected_rows[0]]
        card_id = row["card_id"]
        res = server.test_client().delete("/api/admin/cards", json={"card_id": card_id})
        if res.status_code == 200:
            return "Card deleted"
        else:
            return f"Error: {res.get_json()}"
    return ""

@app.callback(
    Output("rules-msg", "children"),
    [Input("add-rule-btn", "n_clicks"), Input("delete-rule-btn", "n_clicks")],
    [State("rule-card-id", "value"), State("rule-from", "value"), State("rule-to", "value"), State("rule-attrs", "value"),
     State("rules-table", "selected_rows"), State("rules-table", "data")]
)
def handle_rules(add_click, delete_click, card_id, rfrom, rto, rattrs, selected_rows, table_data):
    triggered = ctx.triggered_id
    if triggered == "add-rule-btn":
        if not card_id:
            return "card_id required"
        # parse attributes
        try:
            attrs = json.loads(rattrs) if rattrs else {}
        except Exception as e:
            return f"Invalid attributes JSON: {e}"
        res = server.test_client().post("/api/admin/access_rule", json={
            "card_id": card_id, "access_from": rfrom, "access_to": rto, "attributes": attrs
        })
        if res.status_code == 200:
            return "Rule added"
        else:
            return f"Error: {res.get_json()}"
    if triggered == "delete-rule-btn":
        if not selected_rows:
            return "Select a rule first"
        row = table_data[selected_rows[0]]
        rule_id = row["id"]
        res = server.test_client().delete("/api/admin/access_rule", json={"rule_id": rule_id})
        if res.status_code == 200:
            return "Rule deleted"
        else:
            return f"Error: {res.get_json()}"
    return ""

@app.callback(
    Output("pi-msg", "children"),
    [Input("add-pi-btn", "n_clicks"), Input("toggle-pi-btn", "n_clicks")],
    [State("new-pi-id", "value"), State("new-pi-desc", "value"), State("new-pi-api-key", "value"),
     State("pi-table", "selected_rows"), State("pi-table", "data")]
)
def handle_pi(add_click, toggle_click, new_id, new_desc, new_api_key, selected_rows, table_data):
    triggered = ctx.triggered_id
    if triggered == "add-pi-btn":
        if not new_id or not new_api_key:
            return "device_id and api_key required"
        # Hash key and insert
        if PiDevice.query.filter_by(device_id=new_id).first():
            return "device already exists"
        api_key_hash = generate_password_hash(new_api_key)
        d = PiDevice(device_id=new_id, api_key_hash=api_key_hash, description=new_desc)
        db.session.add(d)
        db.session.commit()
        return "Pi device added (store plaintext key securely on device!)"
    if triggered == "toggle-pi-btn":
        if not selected_rows:
            return "Select device row"
        row = table_data[selected_rows[0]]
        device_id = row["device_id"]
        d = PiDevice.query.filter_by(device_id=device_id).first()
        if not d:
            return "Device not found"
        d.enabled = not d.enabled
        db.session.commit()
        return f"Device {device_id} enabled={d.enabled}"
    return ""

# -----------------------
# Initialize DB helper route (for dev only)
# -----------------------
@server.route("/dev/init_db")
def dev_init_db():
    # only allow on debug/dev
    if server.debug or os.environ.get("DEV_INIT") == "1":
        db.create_all()
        return "db initialized"
    return "disabled", 403

# -----------------------
# Run
# -----------------------
if __name__ == "__main__":
    # Safety: ensure redirect uri uses the right FRONTEND_BASE
    print("Starting Dash app. FRONTEND_BASE:", FRONTEND_BASE)
    server.run(host="0.0.0.0", port=8050, debug=True)
else:
    print("Dash app loaded as module.")
    with server.app_context():
        db.create_all()  # ensure tables exist
