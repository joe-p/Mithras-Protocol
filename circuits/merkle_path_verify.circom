pragma circom 2.1.5;

include "./mimc.circom";

template MerklePathVerify(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathSelectors[depth];
    signal input root;

    component mimcHashers[depth];
    signal computedHash[depth + 1];
    
    signal leftInput[depth];
    signal rightInput[depth];
    signal leftTerm1[depth];
    signal leftTerm2[depth];
    signal rightTerm1[depth];
    signal rightTerm2[depth];

    computedHash[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        mimcHashers[i] = MiMC_Sum(2);
        
        leftTerm1[i] <== (1 - pathSelectors[i]) * computedHash[i];
        leftTerm2[i] <== pathSelectors[i] * pathElements[i];
        leftInput[i] <== leftTerm1[i] + leftTerm2[i];
        
        rightTerm1[i] <== pathSelectors[i] * computedHash[i];
        rightTerm2[i] <== (1 - pathSelectors[i]) * pathElements[i];
        rightInput[i] <== rightTerm1[i] + rightTerm2[i];
        
        mimcHashers[i].msgs[0] <== leftInput[i];
        mimcHashers[i].msgs[1] <== rightInput[i];
        
        computedHash[i + 1] <== mimcHashers[i].out;
    }

    root === computedHash[depth];
}

component main = MerklePathVerify(32);
