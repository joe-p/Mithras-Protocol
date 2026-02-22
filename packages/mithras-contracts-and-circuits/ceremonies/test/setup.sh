#!/bin/bash

cd "$(dirname "$0")"
CEREMONY_DIR="$(pwd)"

set -euo pipefail

PROJECT_DIR="$(cd "$CEREMONY_DIR/../.." && pwd)"
SNARKJS_BIN="$PROJECT_DIR/node_modules/.bin/snarkjs"
SNARKJS_CLI="$PROJECT_DIR/node_modules/snarkjs/build/cli.cjs"

snarkjs() {
    if [ -x "$SNARKJS_BIN" ]; then
        "$SNARKJS_BIN" "$@"
        return 0
    fi

    if [ -f "$SNARKJS_CLI" ]; then
        node "$SNARKJS_CLI" "$@"
        return 0
    fi

    if command -v snarkjs >/dev/null 2>&1; then
        snarkjs "$@"
        return 0
    fi

    echo "[setup.sh] ERROR: Could not find snarkjs (expected $SNARKJS_BIN or $SNARKJS_CLI, or snarkjs on PATH)." >&2
    exit 1
}

if [ ! -f "$CEREMONY_DIR/pot16_final.ptau" ]; then
    # snarkjs powersoftau new bls12381 16 "$CEREMONY_DIR/pot16_0000.ptau" -v
    snarkjs powersoftau new bn254 16 "$CEREMONY_DIR/pot16_0000.ptau" -v
    echo "blah" | snarkjs powersoftau contribute "$CEREMONY_DIR/pot16_0000.ptau" "$CEREMONY_DIR/pot16_0001.ptau" --name="First contribution" -v
    snarkjs powersoftau prepare phase2 "$CEREMONY_DIR/pot16_0001.ptau" "$CEREMONY_DIR/pot16_final.ptau" -v
    snarkjs powersoftau verify "$CEREMONY_DIR/pot16_final.ptau"
fi
