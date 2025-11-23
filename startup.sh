#!/bin/bash

# Install uv if not already installed
if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
fi

# Sync dependencies using uv
cd /home/site/wwwroot
uv sync

# Run the application using the virtual environment
uv run python main.py
