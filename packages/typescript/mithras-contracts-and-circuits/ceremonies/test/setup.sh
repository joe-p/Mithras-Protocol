if [ ! -f pot16_final.ptau ]; then
    pnpm snarkjs powersoftau new bls12381 16 pot16_0000.ptau -v
    echo "blah" | pnpm snarkjs powersoftau contribute pot16_0000.ptau pot16_0001.ptau --name="First contribution" -v
    pnpm snarkjs powersoftau prepare phase2 pot16_0001.ptau pot16_final.ptau -v
    pnpm snarkjs powersoftau verify pot16_final.ptau
fi
