pragma circom 2.1.5;

include "./mimc.circom";

template Deposit() {
    signal input amount;
    signal input receiver;

    // Private inputs
    signal input spending_secret;
    signal input nullifier_secret;

    // Public output
    signal output commitment;

    // Hash the 4-tuple in order using MiMC_Sum(4)
    component H = MiMC_Sum(4);
    H.msgs[0] <== spending_secret;
    H.msgs[1] <== nullifier_secret;
    H.msgs[2] <== amount;
    H.msgs[3] <== receiver;

    commitment <== H.out;
}

component main = Deposit();
