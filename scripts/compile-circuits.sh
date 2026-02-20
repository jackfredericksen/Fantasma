#!/usr/bin/env bash
# Compile Cairo circuits to Sierra JSON
# Requires: scarb (https://docs.swmansion.com/scarb/)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CIRCUITS_DIR="$PROJECT_ROOT/circuits"

echo "Compiling Cairo circuits..."

if ! command -v scarb &>/dev/null; then
    echo "Error: scarb not found. Install it from https://docs.swmansion.com/scarb/"
    exit 1
fi

cd "$CIRCUITS_DIR"

# Build circuits
scarb build

# Check output
SIERRA_JSON="$CIRCUITS_DIR/target/dev/fantasma_circuits.sierra.json"
if [ -f "$SIERRA_JSON" ]; then
    SIZE=$(wc -c < "$SIERRA_JSON" | tr -d ' ')
    HASH=$(shasum -a 256 "$SIERRA_JSON" | cut -d' ' -f1)
    echo "Compiled successfully:"
    echo "  Output: $SIERRA_JSON"
    echo "  Size:   $SIZE bytes"
    echo "  SHA256: $HASH"
else
    echo "Error: Sierra JSON not found at $SIERRA_JSON"
    exit 1
fi

# Run circuit tests
echo ""
echo "Running circuit tests..."
scarb test

echo ""
echo "All circuits compiled and tested successfully."
