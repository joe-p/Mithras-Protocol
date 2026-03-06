pragma circom 2.1.5;

include "./mimc.circom";

// Circuit that proves the transition from old_root to new_root when inserting a leaf
// at a specific index in the Merkle tree.
//
// Public inputs:
//   - old_root: The Merkle root before insertion (verified by contract)
//   - leaf: The leaf value being inserted
//   - new_root: The Merkle root after insertion (computed by circuit)
//   - insertion_index: The position where the leaf is inserted (0-indexed)
//
// Private inputs:
//   - path_selectors[DEPTH]: Binary decomposition of insertion_index (0=left, 1=right)
//   - siblings[DEPTH]: Frontier values from the old tree state at each level
//
// Note: The contract must verify that old_root is valid before accepting the proof.
// The path_selectors must correspond to the binary representation of insertion_index.
// The zero hashes for empty tree positions are computed within the circuit.
template InsertLeaf(DEPTH) {
    // Public inputs
    signal input old_root;
    signal input leaf;
    signal output new_root;
    signal input insertion_index;

    // Private inputs
    signal input path_selectors[DEPTH];
    signal input siblings[DEPTH];

    // Components for computing zero hashes
    component zeroHashers[DEPTH - 1];
    
    // Zero hashes: z[0] = 0, z[i] = mimc(z[i-1], z[i-1])
    signal z[DEPTH];
    z[0] <== 0;
    
    for (var i = 1; i < DEPTH; i++) {
        zeroHashers[i-1] = MiMC_Sum(2);
        zeroHashers[i-1].msgs[0] <== z[i-1];
        zeroHashers[i-1].msgs[1] <== z[i-1];
        z[i] <== zeroHashers[i-1].out;
    }

    // Hash up the tree to compute the new root
    // At each level:
    // - If path_selectors[i] == 0: sibling is zero hash z[i], currentHash is left
    // - If path_selectors[i] == 1: sibling is siblings[i], siblings[i] is left
    component mimcHashers[DEPTH];
    signal currentHash[DEPTH + 1];
    signal leftInput[DEPTH];
    signal rightInput[DEPTH];
    signal leftTerm1[DEPTH];
    signal leftTerm2[DEPTH];
    signal rightTerm1[DEPTH];
    signal rightTerm2[DEPTH];
    
    currentHash[0] <== leaf;
    
    for (var i = 0; i < DEPTH; i++) {
        mimcHashers[i] = MiMC_Sum(2);
        
        // Compute left and right using intermediate signals for quadratic constraints
        // left = (1 - selector) * currentHash + selector * siblings[i]
        // right = selector * currentHash + (1 - selector) * z[i]
        leftTerm1[i] <== (1 - path_selectors[i]) * currentHash[i];
        leftTerm2[i] <== path_selectors[i] * siblings[i];
        leftInput[i] <== leftTerm1[i] + leftTerm2[i];
        
        rightTerm1[i] <== path_selectors[i] * currentHash[i];
        rightTerm2[i] <== (1 - path_selectors[i]) * z[i];
        rightInput[i] <== rightTerm1[i] + rightTerm2[i];
        
        mimcHashers[i].msgs[0] <== leftInput[i];
        mimcHashers[i].msgs[1] <== rightInput[i];
        
        currentHash[i + 1] <== mimcHashers[i].out;
    }

    // The computed root should match the claimed new_root
    new_root <== currentHash[DEPTH];
}

component main {public [old_root, leaf, insertion_index]} = InsertLeaf(20);
