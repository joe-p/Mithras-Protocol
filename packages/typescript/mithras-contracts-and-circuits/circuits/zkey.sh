bash ../ceremonies/test/setup.sh

circom --r1cs --wasm --c --sym --inspect deposit.circom --prime bls12381
pnpm snarkjs plonk setup deposit.r1cs ../ceremonies/test/pot16_final.ptau deposit_test.zkey

circom --r1cs --wasm --c --sym --inspect spend.circom --prime bls12381
pnpm snarkjs plonk setup spend.r1cs ../ceremonies/test/pot16_final.ptau spend_test.zkey
