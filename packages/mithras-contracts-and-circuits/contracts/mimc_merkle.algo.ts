import {
  assert,
  Box,
  clone,
  Contract,
  FixedArray,
  GlobalState,
  op,
  uint64,
  contract,
  ensureBudget,
  BoxMap,
  BigUint,
  LogicSig,
  gtxn,
  Txn,
  TemplateVar,
  Account,
  bytes,
} from "@algorandfoundation/algorand-typescript";
import { TREE_DEPTH } from "../src/constants";
import {
  decodeArc4,
  Uint,
  Uint256,
} from "@algorandfoundation/algorand-typescript/arc4";

const ROOT_CACHE_SIZE = 50;

const EPOCHS_PER_BOX = 32;

// Base cost for mimc is 10 uALGO, and each bytes<32> costs 550 uALGO
const MIMC_OPCODE_COST = 1110 * TREE_DEPTH;

@contract({ avmVersion: 11 })
export class MimcMerkle extends Contract {
  rootCache = Box<FixedArray<Uint256, typeof ROOT_CACHE_SIZE>>({ key: "r" });

  rootCounter = GlobalState<uint64>({ key: "c" });

  nextLeafIndex = GlobalState<uint64>({ key: "i" });

  zeroHashes = Box<Subtree>({ key: "z" });

  // Track epochs and cache the last computed root for sealing
  epochId = GlobalState<uint64>({ key: "e" });

  lastCommittedLeaf = GlobalState<Uint256>({ key: "ll" });

  epochBoxes = BoxMap<uint64, FixedArray<Uint256, typeof EPOCHS_PER_BOX>>({
    keyPrefix: "e",
  });

  commitmentLsigAddr = GlobalState<Account>({ key: "a" });

  pendingLeafs = BoxMap<Uint256, bytes<0>>({ keyPrefix: "p" });

  subtree = Box<Subtree>({ key: "s" });

  protected bootstrap(commitLeafLsig: Account): void {
    this.commitmentLsigAddr.value = commitLeafLsig;
    ensureBudget(MIMC_OPCODE_COST);
    const tree: Subtree = new FixedArray<Uint256, typeof TREE_DEPTH>();

    tree[0] = new Uint256(0);

    for (let i: uint64 = 1; i < TREE_DEPTH; i++) {
      tree[i] = new Uint256(
        op.mimc(
          op.MimcConfigurations.BLS12_381Mp111,
          tree[i - 1].bytes.concat(tree[i - 1].bytes),
        ),
      );
    }

    this.rootCounter.value = 0;
    this.nextLeafIndex.value = 0;
    this.rootCache.create();
    this.zeroHashes.value = clone(tree);
    this.epochId.value = 0;
    // The empty tree root
    this.addRoot(tree[TREE_DEPTH - 1]);
  }

  protected currentRoot(): Uint256 {
    return this.rootCache.value[(this.rootCounter.value - 1) % ROOT_CACHE_SIZE];
  }

  protected addLeaf(leafHash: Uint256): void {
    assert(!this.pendingLeafs(leafHash).exists, "leaf already pending");
    this.pendingLeafs(leafHash).create();
  }

  // Seal the current full (or partial) tree as an epoch and reset to a new tree
  protected sealAndRotate(): void {
    // Optional: require at least one leaf in the epoch
    assert(this.nextLeafIndex.value > 0, "nothing to seal");

    const epoch = this.epochId.value;
    const epochBoxKey: uint64 = epoch / EPOCHS_PER_BOX;
    const index: uint64 = epoch % EPOCHS_PER_BOX;

    const epochBox = this.epochBoxes(epochBoxKey);
    epochBox.create();

    epochBox.value[index] = this.currentRoot();

    // Prepare next epoch: reset tree state
    this.epochId.value = epoch + 1;
    this.nextLeafIndex.value = 0;
    const zeros = clone(this.zeroHashes.value);

    // Reset recent root cache and seed with empty root
    this.rootCounter.value = 0;

    // Optionally clear existing cache by recreating
    this.rootCache.delete();
    this.rootCache.create();
    const emptyRoot = zeros[TREE_DEPTH - 1];
    this.subtree.value = zeros;
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

  /**
   * Add a leaf to the merkle tree in a separate transaction signed by the commitment logic sig.
   * This will be significantly cheaper (~30x cheaper) than `commitLeafInAppCall` but it is susceptible to
   * race conditions. Without coordination only one sender will be able to make commitments per block and it'll be whichever
   * sender gets their transaction group included first.
   */
  protected commitLeafWithLsig(
    commitmentLsig: gtxn.Transaction,
    args: CommitLeafArgs,
  ): void {
    assert(
      commitmentLsig.sender === this.commitmentLsigAddr.value,
      "invalid commitment Lsig",
    );

    assert(
      args.lastLeaf === this.lastCommittedLeaf.value,
      "previous leaf mismatch",
    );

    assert(
      args.newLeafIndex === this.nextLeafIndex.value,
      "unexpected leaf index",
    );

    assert(
      args.currentSubtree === this.subtree.value,
      "previous subtree mismatch",
    );

    assert(this.currentRoot() === args.currentRoot, "current root mismatch");
    this.commitLeafRootAndSubtree(args.newLeaf, args.newRoot, args.newSubtree);
  }

  /**
   * Add a leaf to the merkle tree in an app call. Compared to `commitLeafWithLsig` this method will be much more
   * expensive to cover the cost of op-ups, but it allows a leaf to committed without the risk of a race condition.
   * This is useful when the ability to spend the UTXO instantly is required.
   */
  protected commitLeafInAppCall(leaf: Uint256): void {
    ensureBudget(MIMC_OPCODE_COST);
    const { root, subtree } = calculateRootAndSubtree(
      leaf,
      this.nextLeafIndex.value,
      this.subtree.value,
    );

    assert(this.isValidRoot(root), "invalid leaf: root not recognized");
    this.commitLeafRootAndSubtree(leaf, root, subtree);
  }

  private commitLeafRootAndSubtree(
    newLeaf: Uint256,
    root: Uint256,
    subtree: Subtree,
  ): void {
    assert(this.pendingLeafs(newLeaf).delete(), "leaf not pending");
    this.lastCommittedLeaf.value = newLeaf;
    this.addRoot(root);
    this.nextLeafIndex.value += 1;
    this.subtree.value = subtree;
  }
}

export type Subtree = FixedArray<Uint256, typeof TREE_DEPTH>;

export type CommitLeafArgs = {
  newLeaf: Uint256; // 32 bytes
  lastLeaf: Uint256; // 32 + 32 = 64 bytes
  newLeafIndex: uint64; // 64 + 8 = 72 bytes
  currentSubtree: Subtree; // 72 + (32 * TREE_DEPTH) = 72 + (32 * 20) = 712 bytes
  currentRoot: Uint256; // 712 + 32 = 744 bytes
  newRoot: Uint256; // 744 + 32 = 776 bytes
  newSubtree: Subtree; // 776 + (32 * TREE_DEPTH) = 776 + (32 * 20) = 1,416 bytes
};

export class CommitLeaf extends LogicSig {
  program(): boolean {
    const appl = gtxn.ApplicationCallTxn(Txn.groupIndex + 1);
    const args = decodeArc4<CommitLeafArgs>(appl.appArgs(1));

    const { root: currentRoot, subtree: currentSubtree } =
      calculateRootAndSubtree(
        args.lastLeaf,
        args.newLeafIndex - 1,
        args.currentSubtree,
      );
    assert(currentRoot === args.currentRoot, "old root mismatch");

    const { root: newRoot, subtree: newSubtree } = calculateRootAndSubtree(
      args.newLeaf,
      args.newLeafIndex,
      currentSubtree,
    );

    assert(newRoot === args.newRoot, "new root mismatch");
    assert(newSubtree === args.newSubtree, "new subtree mismatch");
    return true;
  }
}

function calculateRootAndSubtree(
  leaf: Uint256,
  index: uint64,
  subtree: Subtree,
): { root: Uint256; subtree: Subtree } {
  const zeroHashes =
    TemplateVar<FixedArray<Uint256, typeof TREE_DEPTH>>("ZERO_HASHES");

  let left: Uint256;
  let right: Uint256;
  let currentHash = leaf;

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
      op.mimc(
        op.MimcConfigurations.BLS12_381Mp111,
        left.bytes.concat(right.bytes),
      ),
    );

    index >>= 1;
  }

  return { root: currentHash, subtree };
}
