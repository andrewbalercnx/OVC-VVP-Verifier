#!/bin/bash
# Convenience wrapper to restart verifier server from repo root
# Usage: ./scripts/restart-server.sh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$REPO_ROOT/services/verifier/scripts/restart-server.sh" "$@"
