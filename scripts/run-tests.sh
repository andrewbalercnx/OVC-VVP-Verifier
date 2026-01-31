#!/bin/bash
# Convenience wrapper to run verifier tests from repo root
# Usage: ./scripts/run-tests.sh [pytest args...]

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$REPO_ROOT/services/verifier/scripts/run-tests.sh" "$@"
