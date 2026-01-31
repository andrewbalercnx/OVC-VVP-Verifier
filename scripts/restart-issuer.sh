#!/bin/bash
# Convenience wrapper to restart issuer server from repo root
# Usage: ./scripts/restart-issuer.sh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$REPO_ROOT/services/issuer/scripts/restart-server.sh" "$@"
