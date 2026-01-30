#!/bin/bash
# Restart the local uvicorn development server
# Usage: ./scripts/restart-server.sh

# Kill any existing uvicorn processes
pkill -f "uvicorn app.main:app" 2>/dev/null || true

# Determine python path
if [ -d ".venv" ]; then
    PYTHON=".venv/bin/python3"
else
    PYTHON="python3"
fi

# Start server with libsodium library path
echo "Starting uvicorn server on http://localhost:8000..."
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
