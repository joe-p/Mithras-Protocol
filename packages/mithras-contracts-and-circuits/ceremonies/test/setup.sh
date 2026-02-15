#!/bin/bash

cd "$(dirname "$0")"
CEREMONY_DIR="$(pwd)"

if [ ! -f "$CEREMONY_DIR/pot16_final.ptau" ]; then
    pnpm snarkjs powersoftau new bls12381 16 "$CEREMONY_DIR/pot16_0000.ptau" -v
    echo "blah" | pnpm snarkjs powersoftau contribute "$CEREMONY_DIR/pot16_0000.ptau" "$CEREMONY_DIR/pot16_0001.ptau" --name="First contribution" -v
    pnpm snarkjs powersoftau prepare phase2 "$CEREMONY_DIR/pot16_0001.ptau" "$CEREMONY_DIR/pot16_final.ptau" -v
    pnpm snarkjs powersoftau verify "$CEREMONY_DIR/pot16_final.ptau"
fi
