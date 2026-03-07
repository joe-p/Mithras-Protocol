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
const MIMC_OPCODE_COST = 1100 * TREE_DEPTH;

@contract({ avmVersion: 11 })
export class MimcMerkle extends Contract {
  rootCache = Box<FixedArray<Uint256, typeof ROOT_CACHE_SIZE>>({ key: "r" });

  rootCounter = GlobalState<uint64>({ key: "c" });

  nextLeafIndex = GlobalState<uint64>({ key: "i" });

  zeroHashes = Box<FixedArray<Uint256, typeof TREE_DEPTH>>({ key: "z" });

  // Track epochs and cache the last computed root for sealing
  epochId = GlobalState<uint64>({ key: "e" });

  currentRoot = GlobalState<Uint256>({ key: "cr" });

  lastCommittedLeaf = GlobalState<Uint256>({ key: "ll" });

  epochBoxes = BoxMap<uint64, FixedArray<Uint256, typeof EPOCHS_PER_BOX>>({
    keyPrefix: "e",
  });

  commitmentLsigAddr = GlobalState<Account>({ key: "a" });

  pendingLeafs = BoxMap<Uint256, bytes<0>>({ keyPrefix: "p" });

  protected bootstrap(): void {
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

    this.rootCounter.value = 0;
    this.nextLeafIndex.value = 0;
    this.rootCache.create();
    this.zeroHashes.value = clone(tree);
    this.epochId.value = 0;
    // The empty tree root
    this.currentRoot.value = tree[TREE_DEPTH - 1];
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

    epochBox.value[index] = this.currentRoot.value;

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
    this.currentRoot.value = emptyRoot;
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

  protected commitLeaf(
    commitmentLsig: gtxn.Transaction,
    args: CommitLeafArgs,
  ): void {
    assert(
      commitmentLsig.sender === this.commitmentLsigAddr.value,
      "invalid commitment Lsig",
    );

    assert(this.pendingLeafs(args.newLeaf).delete(), "leaf not pending");

    assert(
      args.previousLeaf === this.lastCommittedLeaf.value,
      "previous leaf mismatch",
    );

    assert(
      args.newLeafIndex === this.nextLeafIndex.value,
      "unexpected leaf index",
    );

    assert(
      this.currentRoot.value === args.currentRoot,
      "current root mismatch",
    );

    this.addRoot(args.newRoot);
    this.nextLeafIndex.value = args.newLeafIndex + 1;
  }
}

export type Subtree = FixedArray<Uint256, typeof TREE_DEPTH>;

export type CommitLeafArgs = {
  newLeaf: Uint256; // 32 bytes
  previousLeaf: Uint256; // 32 + 32 = 64 bytes
  newLeafIndex: uint64; // 64 + 8 = 72 bytes
  previousSubtree: Subtree; // 72 + (32 * TREE_DEPTH) = 72 + (32 * 20) = 712 bytes
  currentRoot: Uint256; // 712 + 32 = 744 bytes
  newRoot: Uint256; // 744 + 32 = 776 bytes
};

export class CommitLeaf extends LogicSig {
  program(): boolean {
    const appl = gtxn.ApplicationCallTxn(Txn.groupIndex + 1);
    const args = decodeArc4<CommitLeafArgs>(appl.appArgs(1));

    const { root: currentRoot, subtree: currentSubtree } =
      calculateRootAndSubtree(
        args.previousLeaf,
        args.newLeafIndex - 1,
        args.previousSubtree,
      );
    assert(currentRoot === args.currentRoot, "old root mismatch");

    const { root: newRoot } = calculateRootAndSubtree(
      args.newLeaf,
      args.newLeafIndex,
      currentSubtree,
    );

    assert(newRoot === args.newRoot, "new root mismatch");
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
