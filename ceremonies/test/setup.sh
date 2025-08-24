snarkjs powersoftau new bls12381 16 pot16_0000.ptau -v
echo "blah" | snarkjs powersoftau contribute pot16_0000.ptau pot16_0001.ptau --name="First contribution" -v
snarkjs powersoftau prepare phase2 pot16_0001.ptau pot16_final.ptau -v
snarkjs powersoftau verify pot16_final.ptau
