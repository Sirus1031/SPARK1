#!/bin/bash
set -e

echo "Starting application..."

cd /home/site/wwwroot

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "Syncing dependencies with uv..."
uv sync

echo "Starting Gunicorn server..."
# Use main:server since your Flask app variable is 'server' in main.py
uv run gunicorn main:server \
    --bind=0.0.0.0:8000 \
    --timeout 600 \
    --workers 4 \
    --worker-class sync \
    --access-logfile - \
    --error-logfile - \
    --log-level info
