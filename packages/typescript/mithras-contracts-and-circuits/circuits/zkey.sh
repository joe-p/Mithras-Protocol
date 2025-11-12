cd $(dirname "$0")
CIRCUITS_DIR=$(pwd)

bash ../ceremonies/test/setup.sh

circom --r1cs --wasm --c --sym --inspect $CIRCUITS_DIR/deposit.circom --prime bls12381
pnpm snarkjs plonk setup $CIRCUITS_DIR/deposit.r1cs $CIRCUITS_DIR/../ceremonies/test/pot16_final.ptau $CIRCUITS_DIR/deposit_test.zkey

circom --r1cs --wasm --c --sym --inspect $CIRCUITS_DIR/spend.circom --prime bls12381
pnpm snarkjs plonk setup $CIRCUITS_DIR/spend.r1cs $CIRCUITS_DIR/../ceremonies/test/pot16_final.ptau $CIRCUITS_DIR/spend_test.zkey
