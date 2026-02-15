import {
  assert,
  Box,
  bytes,
  clone,
  Contract,
  FixedArray,
  GlobalState,
  op,
  uint64,
  contract,
  ensureBudget,
  Global,
  BoxMap,
  BigUint,
  emit,
} from "@algorandfoundation/algorand-typescript";
import { TREE_DEPTH } from "../src/constants";
import { Uint, Uint256 } from "@algorandfoundation/algorand-typescript/arc4";

const ROOT_CACHE_SIZE = 50;

const EPOCHS_PER_BOX = 32;

// Base cost for mimc is 10 uALGO, and each bytes<32> costs 550 uALGO
const MIMC_OPCODE_COST = 1100 * TREE_DEPTH;

@contract({ avmVersion: 11 })
export class MimcMerkle extends Contract {
  rootCache = Box<FixedArray<Uint256, typeof ROOT_CACHE_SIZE>>({ key: "r" });

  rootCounter = GlobalState<uint64>({ key: "c" });

  subtree = Box<FixedArray<Uint256, typeof TREE_DEPTH>>({ key: "t" });

  treeIndex = GlobalState<uint64>({ key: "i" });

  zeroHashes = Box<FixedArray<Uint256, typeof TREE_DEPTH>>({ key: "z" });

  // Track epochs and cache the last computed root for sealing
  epochId = GlobalState<uint64>({ key: "e" });
  lastComputedRoot = GlobalState<Uint256>({ key: "lr" });

  epochBoxes = BoxMap<uint64, FixedArray<Uint256, typeof EPOCHS_PER_BOX>>({
    keyPrefix: "e",
  });

  protected bootstrap(): void {
    ensureBudget(MIMC_OPCODE_COST);
    const tree = new FixedArray<Uint256, typeof TREE_DEPTH>();

    tree[0] = new Uint256(0);

    for (let i: uint64 = 1; i < TREE_DEPTH; i++) {
      tree[i] = new Uint256(
        BigUint(
          op.mimc(
            op.MimcConfigurations.BLS12_381Mp111,
            tree[i - 1].bytes.concat(tree[i - 1].bytes),
          ),
        ),
      );
    }

    this.rootCounter.value = 0;
    this.treeIndex.value = 0;
    this.rootCache.create();
    this.zeroHashes.value = clone(tree);
    this.subtree.value = clone(tree);
    this.epochId.value = 0;
    // The empty tree root
    this.lastComputedRoot.value = tree[TREE_DEPTH - 1];
  }

  protected addLeaf(leafHash: Uint256): void {
    // Some extra budget needed for the loop logic opcodes
    ensureBudget(MIMC_OPCODE_COST + Global.minTxnFee * 2);

    let index = this.treeIndex.value;

    if (!(index < 2 ** TREE_DEPTH)) {
      // tree is full — seal current epoch and rotate to a fresh tree
      this.sealAndRotate();
      // refresh local index after rotation
      index = this.treeIndex.value;
    }

    this.treeIndex.value += 1;
    let currentHash = leafHash;
    let left: Uint256;
    let right: Uint256;
    let subtree = clone(this.subtree.value);
    const zeroHashes = clone(this.zeroHashes.value);

    for (let i: uint64 = 0; i < TREE_DEPTH; i++) {
      if ((index & 1) === 0) {
        subtree[i] = currentHash;
        left = currentHash;
        right = zeroHashes[i];
      } else {
        left = subtree[i];
        right = currentHash;
      }

      currentHash = new Uint256(
        BigUint(
          op.mimc(
            op.MimcConfigurations.BLS12_381Mp111,
            left.bytes.concat(right.bytes),
          ),
        ),
      );

      index >>= 1;
    }

    this.subtree.value = clone(subtree);
    this.lastComputedRoot.value = currentHash;
    this.addRoot(currentHash);
  }

  // Seal the current full (or partial) tree as an epoch and reset to a new tree
  protected sealAndRotate(): void {
    // Optional: require at least one leaf in the epoch
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
    const zeros = clone(this.zeroHashes.value);
    this.subtree.value = clone(zeros);

    // Reset recent root cache and seed with empty root
    this.rootCounter.value = 0;

    // Optionally clear existing cache by recreating
    this.rootCache.delete();
    this.rootCache.create();
    const emptyRoot = zeros[TREE_DEPTH - 1];
    this.lastComputedRoot.value = emptyRoot;
    this.addRoot(emptyRoot);
  }

  protected isValidRoot(root: Uint256): boolean {
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
    const index: uint64 = this.rootCounter.value % ROOT_CACHE_SIZE;
    this.rootCache.value[index] = rootHash;

    this.rootCounter.value += 1;
  }
}
