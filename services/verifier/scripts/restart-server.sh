#!/bin/bash
# Restart the local uvicorn development server
# Usage: ./scripts/restart-server.sh

# Determine script and service directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$(dirname "$SERVICE_DIR")")"

# Change to service directory for uvicorn to find app module
cd "$SERVICE_DIR"

# Kill any existing uvicorn processes
pkill -f "uvicorn app.main:app" 2>/dev/null || true

# Determine python path (check both service and repo root)
if [ -d "$SERVICE_DIR/.venv" ]; then
    PYTHON="$SERVICE_DIR/.venv/bin/python3"
elif [ -d "$REPO_ROOT/.venv" ]; then
    PYTHON="$REPO_ROOT/.venv/bin/python3"
else
    PYTHON="python3"
fi

# Start server with libsodium library path
echo "Starting uvicorn server on http://localhost:8000..."
echo "Working directory: $SERVICE_DIR"
DYLD_LIBRARY_PATH="/opt/homebrew/lib" nohup $PYTHON -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload > /tmp/uvicorn.log 2>&1 &

# Wait for server to start
sleep 3

# Check if server is healthy
if curl -s http://localhost:8000/healthz > /dev/null 2>&1; then
    echo "Server started successfully"
    curl -s http://localhost:8000/healthz
else
    echo "Server may still be starting. Check /tmp/uvicorn.log for details"
    tail -10 /tmp/uvicorn.log
fi
