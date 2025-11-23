#!/bin/bash

cd /home/site/wwwroot

# Install uv if needed
if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
fi

# Sync dependencies
uv sync

# Run with gunicorn
uv run gunicorn main:server -b 0.0.0.0:8000 --timeout 600
