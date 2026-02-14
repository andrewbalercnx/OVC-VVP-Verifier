#!/usr/bin/env bash
# request-review-with-context.sh — Context-aware wrapper around request-review.sh.
#
# Auto-selects a context profile based on review type, builds the context pack,
# then delegates to request-review.sh with VVP_REVIEWER set to codex-reviewer.sh.
#
# Usage:
#   ./scripts/request-review-with-context.sh plan <sprint-number> "<title>"
#   ./scripts/request-review-with-context.sh code <sprint-number> "<title>"
#
# Environment:
#   VVP_CONTEXT_PROFILE   Override auto-selected profile
#   VVP_CONTEXT_DISABLE   Set to 1 to skip context packing
#   VVP_REVIEWER          Override the reviewer command
#
set -euo pipefail

if [ $# -lt 3 ]; then
    echo "Usage: $0 <plan|code> <sprint-number> <title>" >&2
    exit 1
fi

REVIEW_TYPE="$1"
SPRINT_NUM="$2"
shift 2
TITLE="$*"

REPO_ROOT="$(git rev-parse --show-toplevel)"

# --- Auto-select profile based on review type --------------------------------
if [ -z "${VVP_CONTEXT_PROFILE:-}" ]; then
    case "$REVIEW_TYPE" in
        plan) export VVP_CONTEXT_PROFILE="review-plan" ;;
        code) export VVP_CONTEXT_PROFILE="review-code" ;;
        *)    export VVP_CONTEXT_PROFILE="default" ;;
    esac
fi

echo "[context] Review type: $REVIEW_TYPE → profile: $VVP_CONTEXT_PROFILE"

# --- Build context pack ------------------------------------------------------
if [ "${VVP_CONTEXT_DISABLE:-0}" != "1" ]; then
    "$REPO_ROOT/scripts/build_context_pack.sh" "$VVP_CONTEXT_PROFILE"
else
    echo "[context] Context packing disabled"
fi

# --- Set reviewer if not overridden ------------------------------------------
if [ -z "${VVP_REVIEWER:-}" ]; then
    export VVP_REVIEWER="$REPO_ROOT/scripts/codex-reviewer.sh"
fi

# --- Delegate to request-review.sh -------------------------------------------
exec "$REPO_ROOT/scripts/request-review.sh" "$REVIEW_TYPE" "$SPRINT_NUM" "$TITLE"
