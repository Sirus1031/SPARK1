#!/bin/bash
set -e

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Starting Gunicorn..."
gunicorn main:server \
    --bind=0.0.0.0:8000 \
    --timeout 600 \
    --workers 4 \
    --access-logfile - \
    --error-logfile -