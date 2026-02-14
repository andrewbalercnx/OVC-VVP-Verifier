#!/usr/bin/env bash
# build_context_pack.sh — Assemble a KERI/ACDC/vLEI/VVP context pack from skill references.
#
# Usage:
#   ./scripts/build_context_pack.sh [profile]
#
# Profiles:
#   review-plan   All 6 references (glossary, keri, acdc, vlei, vvp, source-map)
#   review-code   4 references   (glossary, acdc, vvp, source-map)
#   default       2 references   (glossary, source-map)
#
# Environment:
#   VVP_CONTEXT_PROFILE   Override profile (takes precedence over $1)
#   VVP_CONTEXT_DISABLE   Set to 1 to skip context packing entirely
#
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SKILL_DIR="$REPO_ROOT/codex/skills/keri-acdc-vlei-vvp/references"
OUTPUT_DIR="$REPO_ROOT/codex/context"
OUTPUT_FILE="$OUTPUT_DIR/CONTEXT_PACK.md"

# --- Early exit if disabled ------------------------------------------------
if [ "${VVP_CONTEXT_DISABLE:-0}" = "1" ]; then
    echo "[context] Context packing disabled (VVP_CONTEXT_DISABLE=1)"
    rm -f "$OUTPUT_FILE"
    exit 0
fi

# --- Resolve profile -------------------------------------------------------
PROFILE="${VVP_CONTEXT_PROFILE:-${1:-default}}"

case "$PROFILE" in
    review-plan|review-code|default) ;;
    *)
        echo "ERROR: Unknown profile '$PROFILE'. Valid: review-plan, review-code, default" >&2
        exit 1
        ;;
esac

# --- Validate skill directory exists ----------------------------------------
if [ ! -d "$SKILL_DIR" ]; then
    echo "ERROR: Skill reference directory not found: $SKILL_DIR" >&2
    exit 1
fi

# --- Select files for profile -----------------------------------------------
declare -a FILES
case "$PROFILE" in
    review-plan)
        FILES=(
            "$SKILL_DIR/glossary.md"
            "$SKILL_DIR/keri.md"
            "$SKILL_DIR/acdc.md"
            "$SKILL_DIR/vlei.md"
            "$SKILL_DIR/vvp.md"
            "$SKILL_DIR/source-map.md"
        )
        ;;
    review-code)
        FILES=(
            "$SKILL_DIR/glossary.md"
            "$SKILL_DIR/acdc.md"
            "$SKILL_DIR/vvp.md"
            "$SKILL_DIR/source-map.md"
        )
        ;;
    default)
        FILES=(
            "$SKILL_DIR/glossary.md"
            "$SKILL_DIR/source-map.md"
        )
        ;;
esac

# --- Validate all files exist -----------------------------------------------
for f in "${FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: Missing reference file: $f" >&2
        exit 1
    fi
done

# --- Assemble context pack --------------------------------------------------
mkdir -p "$OUTPUT_DIR"

{
    echo "# VVP Domain Context Pack"
    echo ""
    echo "Profile: \`$PROFILE\` — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "This context pack provides KERI/ACDC/vLEI/VVP domain knowledge for code review."
    echo "Use it to understand credential structures, verification logic, and project conventions."
    echo ""

    for f in "${FILES[@]}"; do
        echo "---"
        echo ""
        cat "$f"
        echo ""
    done
} > "$OUTPUT_FILE"

LINE_COUNT=$(wc -l < "$OUTPUT_FILE" | tr -d ' ')
echo "[context] Built context pack: profile=$PROFILE, ${#FILES[@]} files, $LINE_COUNT lines → $OUTPUT_FILE"
