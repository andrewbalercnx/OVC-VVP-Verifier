#!/bin/bash
# Restart the local uvicorn development server for VVP Issuer
# Usage: ./scripts/restart-server.sh

# Determine script and service directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$(dirname "$SERVICE_DIR")")"

# Change to service directory for uvicorn to find app module
cd "$SERVICE_DIR"

# Kill any existing issuer uvicorn processes (port 8001)
pkill -f "uvicorn app.main:app.*8001" 2>/dev/null || true

# Determine python path (check both service and repo root)
if [ -d "$SERVICE_DIR/.venv" ]; then
    PYTHON="$SERVICE_DIR/.venv/bin/python3"
elif [ -d "$REPO_ROOT/.venv" ]; then
    PYTHON="$REPO_ROOT/.venv/bin/python3"
else
    PYTHON="python3"
fi

# Start server with libsodium library path
echo "Starting VVP Issuer on http://localhost:8001..."
echo "Working directory: $SERVICE_DIR"
DYLD_LIBRARY_PATH="/opt/homebrew/lib" nohup $PYTHON -m uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload > /tmp/uvicorn-issuer.log 2>&1 &

# Wait for server to start
sleep 3

# Check if server is healthy
if curl -s http://localhost:8001/healthz > /dev/null 2>&1; then
    echo "Issuer started successfully"
    curl -s http://localhost:8001/healthz
else
    echo "Issuer may still be starting. Check /tmp/uvicorn-issuer.log for details"
    tail -10 /tmp/uvicorn-issuer.log
fi
