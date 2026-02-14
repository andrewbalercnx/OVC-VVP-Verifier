#!/usr/bin/env bash
# codex-reviewer.sh — Codex wrapper that prepends VVP context pack to the review prompt.
#
# Called by request-review.sh when VVP_REVIEWER is set to this script.
# Reads the context pack from codex/context/CONTEXT_PACK.md (if present)
# and prepends it to the reviewer prompt before invoking Codex.
#
# Environment:
#   VVP_CODEX_CMD   Override the Codex invocation (default: "codex exec --full-auto")
#
set -euo pipefail

PROMPT="$1"
REPO_ROOT="$(git rev-parse --show-toplevel)"
CONTEXT_FILE="$REPO_ROOT/codex/context/CONTEXT_PACK.md"
CODEX_CMD="${VVP_CODEX_CMD:-codex exec --full-auto}"

# --- Prepend context if available -------------------------------------------
if [ -f "$CONTEXT_FILE" ] && [ -s "$CONTEXT_FILE" ]; then
    CONTEXT=$(cat "$CONTEXT_FILE")
    AUGMENTED_PROMPT="$(cat <<EOF
${CONTEXT}

---

${PROMPT}
EOF
)"
    echo "[reviewer] Prepended context pack ($(wc -l < "$CONTEXT_FILE" | tr -d ' ') lines) to prompt" >&2
else
    AUGMENTED_PROMPT="$PROMPT"
    echo "[reviewer] No context pack found — using raw prompt" >&2
fi

# --- Invoke Codex -----------------------------------------------------------
$CODEX_CMD "$AUGMENTED_PROMPT"
