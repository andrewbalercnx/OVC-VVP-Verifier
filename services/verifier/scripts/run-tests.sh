#!/bin/bash
# Run pytest with libsodium library path for macOS
# Usage: ./scripts/run-tests.sh [pytest args...]
# Examples:
#   ./scripts/run-tests.sh                          # Run all tests
#   ./scripts/run-tests.sh -v                       # Verbose output
#   ./scripts/run-tests.sh tests/test_signature.py  # Run specific file
#   ./scripts/run-tests.sh -k "test_format"         # Run tests matching pattern

# Determine script and service directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$(dirname "$SERVICE_DIR")")"

# Change to service directory for relative paths
cd "$SERVICE_DIR"

# Use .venv if present (check both service and repo root), otherwise system python3
if [ -d "$SERVICE_DIR/.venv" ]; then
    source "$SERVICE_DIR/.venv/bin/activate"
elif [ -d "$REPO_ROOT/.venv" ]; then
    source "$REPO_ROOT/.venv/bin/activate"
fi

DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/ "$@"
