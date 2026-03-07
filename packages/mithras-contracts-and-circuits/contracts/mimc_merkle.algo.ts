import {
  assert,
  Box,
  Contract,
  FixedArray,
  GlobalState,
  op,
  uint64,
  contract,
  ensureBudget,
  BoxMap,
  gtxn,
  bytes,
  Account,
} from "@algorandfoundation/algorand-typescript";
import { TREE_DEPTH } from "../src/constants";
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";

/**
 * PLONK proof structure: G1 points (96B BE) and field evals (32B BE)
 */
export type PlonkProof = {
  // Uncompressed G1 points
  A: bytes<96>;
  B: bytes<96>;
  C: bytes<96>;
  Z: bytes<96>;
  T1: bytes<96>;
  T2: bytes<96>;
  T3: bytes<96>;
  Wxi: bytes<96>;
  Wxiw: bytes<96>;
  // Field evaluations are 32 bytes (SNARKJS internal representation, BE)
  eval_a: Uint256;
  eval_b: Uint256;
  eval_c: Uint256;
  eval_s1: Uint256;
  eval_s2: Uint256;
  eval_zw: Uint256;
};

const ROOT_CACHE_SIZE = 50;

const EPOCHS_PER_BOX = 32;

// Base cost for mimc is 10 uALGO, and each bytes<32> costs 550 uALGO
const MIMC_OPCODE_COST = 1100 * TREE_DEPTH;

@contract({ avmVersion: 11 })
export class MimcMerkle extends Contract {
  rootCache = Box<FixedArray<Uint256, typeof ROOT_CACHE_SIZE>>({ key: "r" });

  cachedRootCounter = GlobalState<uint64>({ key: "c" });

  treeIndex = GlobalState<uint64>({ key: "i" });

  // Track epochs and cache the last computed root for sealing
  epochId = GlobalState<uint64>({ key: "e" });

  lastComputedRoot = GlobalState<Uint256>({ key: "lr" });

  epochBoxes = BoxMap<uint64, FixedArray<Uint256, typeof EPOCHS_PER_BOX>>({
    keyPrefix: "e",
  });

  zeroRoot = GlobalState<Uint256>({ key: "z" });

  commitLeafVerifier = GlobalState<Account>({ key: "lv" });

  pendingLeafs = BoxMap<Uint256, bytes<0>>({ keyPrefix: "p" });

  protected bootstrap(addLeafVerifier: Account): void {
    this.commitLeafVerifier.value = addLeafVerifier;

    ensureBudget(MIMC_OPCODE_COST);
    const tree = new FixedArray<Uint256, typeof TREE_DEPTH>();

    tree[0] = new Uint256(0);

    for (let i: uint64 = 1; i < TREE_DEPTH; i++) {
      tree[i] = new Uint256(
        op.mimc(
          op.MimcConfigurations.BLS12_381Mp111,
          tree[i - 1].bytes.concat(tree[i - 1].bytes),
        ),
      );
    }

    this.cachedRootCounter.value = 0;
    this.treeIndex.value = 0;
    this.rootCache.create();
    this.epochId.value = 0;
    this.lastComputedRoot.value = tree[TREE_DEPTH - 1];
    this.zeroRoot.value = tree[TREE_DEPTH - 1];
  }

  protected addPendingLeaf(leaf: Uint256) {
    this.pendingLeafs(leaf).create();
  }

  protected commitLeaf(
    verifier: gtxn.Transaction,
    signals: Uint256[],
    _proof: PlonkProof,
  ): void {
    assert(
      verifier.sender === this.commitLeafVerifier.value,
      "invalid addLeaf verifier",
    );
    const [newRoot, leaf, insertionIndex] = signals;

    assert(insertionIndex.asUint64() === this.treeIndex.value);
    this.addRoot(newRoot);
    this.pendingLeafs(leaf).delete();
  }

  // Seal the current full (or partial) tree as an epoch and reset to a new tree
  protected sealAndRotate(): void {
    assert(this.treeIndex.value > 0, "nothing to seal");

    const epoch = this.epochId.value;
    const epochBoxKey: uint64 = epoch / EPOCHS_PER_BOX;
    const index: uint64 = epoch % EPOCHS_PER_BOX;

    const epochBox = this.epochBoxes(epochBoxKey);
    epochBox.create();

    epochBox.value[index] = this.lastComputedRoot.value;

    // Prepare next epoch: reset tree state
    this.epochId.value = epoch + 1;
    this.treeIndex.value = 0;

    // Reset recent root cache and seed with empty root
    this.cachedRootCounter.value = 0;

    // recreate the cache
    this.rootCache.delete();
    this.lastComputedRoot.value = this.zeroRoot.value;
  }

  protected isValidRoot(root: Uint256): boolean {
    assert(
      root !== this.zeroRoot.value,
      "invalid root: zero root is not valid",
    );
    ensureBudget(700); // TODO: Determine budget needed here
    for (const validRoot of this.rootCache.value) {
      if (root === validRoot) {
        return true;
      }
    }

    return false;
  }

  // Validate a sealed epoch final root by epochId
  protected isValidSealedRoot(epochId: uint64, root: Uint256): boolean {
    const epochBoxId: uint64 = epochId / EPOCHS_PER_BOX;
    const index: uint64 = epochId % EPOCHS_PER_BOX;
    return this.epochBoxes(epochBoxId).value[index] === root;
  }

  protected addRoot(rootHash: Uint256): void {
    const index: uint64 = this.cachedRootCounter.value % ROOT_CACHE_SIZE;
    this.rootCache.value[index] = rootHash;
    this.lastComputedRoot.value = rootHash;

    this.cachedRootCounter.value += 1;
  }
}
