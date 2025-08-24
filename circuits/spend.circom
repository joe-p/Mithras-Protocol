pragma circom 2.1.5;

include "./mimc.circom";
include "./merkle_path_verify.circom";


// Default tree depth to 32 (matches MerklePathVerify main)
template Spend(DEPTH) {
    // Public inputs
    signal input fee;
    signal input utxo_spender; // P' (receiver of UTXO)

    // Private inputs
    signal input utxo_spending_secret;
    signal input utxo_nullifier_secret;
    signal input utxo_amount;

    signal input path_selectors[DEPTH];
    signal input utxo_path[DEPTH];

    signal input out0_amount;
    signal input out0_receiver;
    signal input out0_spending_secret;
    signal input out0_nullifier_secret;

    signal input out1_amount;
    signal input out1_receiver;
    signal input out1_spending_secret;
    signal input out1_nullifier_secret;

    // Public outputs
    signal output out0_commitment;
    signal output out1_commitment;
    signal output utxo_root;
    signal output utxo_nullifier;



    // Compute the UTXO commitment leaf
    component H_utxo = MiMC_Sum(4);
    H_utxo.msgs[0] <== utxo_spending_secret;
    H_utxo.msgs[1] <== utxo_nullifier_secret;
    H_utxo.msgs[2] <== utxo_amount;
    H_utxo.msgs[3] <== utxo_spender;
    signal utxo_commitment;
    utxo_commitment <== H_utxo.out;

    // Verify Merkle path to derive utxo_root
    component mpv = MerklePathVerify(DEPTH);
    mpv.leaf <== utxo_commitment;
    for (var i = 0; i < DEPTH; i++) {
        mpv.pathElements[i] <== utxo_path[i];
        mpv.pathSelectors[i] <== path_selectors[i];
    }
    // Read computed root from MPV and expose it as public output
    utxo_root <== mpv.root;

    // Balance constraint: out0 + out1 + fee = utxo_amount
    // Enforce by equality with zero
    signal sumOuts;
    sumOuts <== out0_amount + out1_amount + fee;
    sumOuts === utxo_amount;

    // Compute output commitments
    component H_out0 = MiMC_Sum(4);
    H_out0.msgs[0] <== out0_spending_secret;
    H_out0.msgs[1] <== out0_nullifier_secret;
    H_out0.msgs[2] <== out0_amount;
    H_out0.msgs[3] <== out0_receiver;
    out0_commitment <== H_out0.out;

    component H_out1 = MiMC_Sum(4);
    H_out1.msgs[0] <== out1_spending_secret;
    H_out1.msgs[1] <== out1_nullifier_secret;
    H_out1.msgs[2] <== out1_amount;
    H_out1.msgs[3] <== out1_receiver;
    out1_commitment <== H_out1.out;

    // Compute nullifier for spent UTXO
    component H_null = MiMC_Sum(2);
    H_null.msgs[0] <== utxo_commitment;
    H_null.msgs[1] <== utxo_nullifier_secret;
    utxo_nullifier <== H_null.out;
}

component main = Spend(32);
