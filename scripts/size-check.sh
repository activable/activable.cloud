#!/bin/bash
# Binary size check: validates that the stripped binary is <= 50MB.
# 50MB binary-size budget (enforced in CI).

set -e

BINARY="${1:-./go/bin/activable}"
MAX_SIZE=$((50 * 1024 * 1024))  # 50 MB in bytes

if [ ! -f "$BINARY" ]; then
    echo "Error: binary not found at $BINARY"
    exit 1
fi

# Strip the binary
TEMP_STRIPPED=$(mktemp)
cp "$BINARY" "$TEMP_STRIPPED"
strip "$TEMP_STRIPPED" 2>/dev/null || true

SIZE=$(stat -f%z "$TEMP_STRIPPED" 2>/dev/null || stat -c%s "$TEMP_STRIPPED" 2>/dev/null)
SIZE_MB=$((SIZE / 1024 / 1024))

echo "Binary size: ${SIZE_MB}MB (limit: 50MB)"

rm -f "$TEMP_STRIPPED"

if [ "$SIZE" -gt "$MAX_SIZE" ]; then
    echo "Error: binary exceeds 50MB limit"
    exit 1
fi

echo "OK: binary size check passed"
exit 0
