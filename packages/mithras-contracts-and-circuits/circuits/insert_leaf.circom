pragma circom 2.1.5;

include "./mimc.circom";

// Circuit that proves the transition from old_root to new_root when inserting a leaf
// at a specific index in the Merkle tree.
//
// Public signals:
//   - leaf: The leaf value being inserted
//   - new_root: The Merkle root after insertion (computed by circuit)
//   - index: The insertion index computed from path_selectors
//
// Private inputs:
//   - path_selectors[DEPTH]: Binary decomposition of insertion_index (0=left, 1=right)
//   - siblings[DEPTH]: Frontier values from the old tree state at each level
template InsertLeaf(DEPTH) {
    // Public inputs
    signal output new_root;
    signal output index;
    signal input leaf;

    // Private inputs
    signal input path_selectors[DEPTH];
    signal input siblings[DEPTH];

    // Precomputed zero hashes: z[0] = 0, z[i] = mimc(z[i-1], z[i-1])
    // These are constant values that don't need to be computed in the circuit
    var z[DEPTH];
    z[0] = 0;
    z[1] = 25810511146743581925833569126742549767512568920378807285358604345673176141381;
    z[2] = 48633631729557618206115024850473558723608917499001828124654165418806894973199;
    z[3] = 271844641933920704909541036058445788326497217356604197269777270414128231100;
    z[4] = 6310889230621472771532712673138966318376115275603472785150511771667973213870;
    z[5] = 5249590367808378787858051563104488775443984938574576596848409786349595770762;
    z[6] = 47168934121733901228505379135581425239624901971016943751482456684501943131862;
    z[7] = 18330698742777627048886063082430764604091239496040258273561339812250250491211;
    z[8] = 3969095639501722722819471700571841005023685206940810851661057658656922051602;
    z[9] = 5579513946522297163017972506334885330352794733812226145130184151062796876055;
    z[10] = 42832916378722882543838397858730128010507860319902246806690383475452696552075;
    z[11] = 26594741062512685912491488800587747513197983351136240797385971245938766324680;
    z[12] = 37523206643844187211789544958019179675421274671932497226886980693509578261643;
    z[13] = 43432632098606229010503330939714720247662431864165951842570857801731111938191;
    z[14] = 19042001408623833816432134280743862360303492193467649059940969842891055637409;
    z[15] = 29524611960016000705855544246944580197873445726526032559111812226455507066554;
    z[16] = 6348767380142817434312731537457524464847940954981725534017631744770074054080;
    z[17] = 22315980541768585939184248671720420420944124952224611159901923862234670816866;
    z[18] = 48339000443090224883626530230600227761753123107720117694502329877285573774241;
    z[19] = 19708380298477335979813740936516997493896150481160724622407987439841366011069;

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
        
        // Constrain path_selectors[i] to be binary (0 or 1)
        path_selectors[i] * (1 - path_selectors[i]) === 0;
        
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

    // Compute index from path_selectors (binary decomposition)
    // index = Σ(path_selectors[i] * 2^i) for i from 0 to DEPTH-1
    var computed_index = 0;
    for (var i = 0; i < DEPTH; i++) {
        computed_index += path_selectors[i] * (1 << i);
    }
    index <== computed_index;

    // The computed root should match the claimed new_root
    new_root <== currentHash[DEPTH];
}

component main {public [leaf]} = InsertLeaf(20);
