#!/bin/bash
# Run VVP Issuer tests with proper environment setup.
#
# Usage:
#   ./scripts/run-tests.sh              # Run all tests
#   ./scripts/run-tests.sh -v           # Verbose output
#   ./scripts/run-tests.sh tests/test_health.py  # Run specific file
#   ./scripts/run-tests.sh -k "test_create"      # Run tests matching pattern

set -e

# Navigate to issuer service directory
cd "$(dirname "$0")/.."

# Set library path for libsodium on macOS
export DYLD_LIBRARY_PATH="/opt/homebrew/lib:$DYLD_LIBRARY_PATH"

# Ensure we're using the right Python path
export PYTHONPATH="$(pwd):$(pwd)/../../common:$(pwd)/../../keripy/src:$PYTHONPATH"

# Run pytest with any provided arguments
python3 -m pytest "$@"
