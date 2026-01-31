#!/bin/bash
# Convenience wrapper to monitor Azure deployment from repo root
# Usage: ./scripts/monitor-azure-deploy.sh [max_attempts]

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$REPO_ROOT/services/verifier/scripts/monitor-azure-deploy.sh" "$@"
