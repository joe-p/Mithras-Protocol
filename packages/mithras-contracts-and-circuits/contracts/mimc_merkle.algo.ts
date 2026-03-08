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
  LogicSig,
  gtxn,
  Txn,
  TemplateVar,
  Account,
} from "@algorandfoundation/algorand-typescript";
import { TREE_DEPTH } from "../src/constants";
import {
  decodeArc4,
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

  nextCommittedLeafTreeIndex = GlobalState<uint64>({ key: "i" });

  nextPendingLeafTreeIndex = GlobalState<uint64>({ key: "p" });

  zeroHashes = Box<Subtree>({ key: "z" });

  // Track epochs and cache the last computed root for sealing
  epochId = GlobalState<uint64>({ key: "e" });

  lastCommittedLeaf = GlobalState<Uint256>({ key: "ll" });

  epochBoxes = BoxMap<uint64, FixedArray<Uint256, typeof EPOCHS_PER_BOX>>({
    keyPrefix: "e",
  });

  commitmentLsigAddr = GlobalState<Account>({ key: "a" });

  pendingLeaves = BoxMap<Uint256, uint64>({ keyPrefix: "p" });

  epochEndedOnIndex = GlobalState<uint64>({ key: "ee" });

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

    this.zeroHashes.value = clone(tree);
    this.epochId.value = 0;
    this.rootCache.create();

    const sentinelLeaf = new Uint256(this.epochId.value);
    this.addPendingLeaf(sentinelLeaf);

    const { root } = calculateRootAndSubtree(sentinelLeaf, 0, tree);
    assert(this.pendingLeaves(sentinelLeaf).delete(), "sentinel not pending");
    this.lastCommittedLeaf.value = sentinelLeaf;
    this.addRoot(root);
    this.nextCommittedLeafTreeIndex.value = 1;
  }

  private indexNearMax(index: uint64): boolean {
    const maxLeafs = 2 ** TREE_DEPTH;
    return index > maxLeafs - maxLeafs / 100;
  }

  private sealEpoch(): void {
    assert(
      this.nextCommittedLeafTreeIndex.value === this.epochEndedOnIndex.value,
      "epoch not ready to seal, not all pending leaves committed",
    );

    // Seal the OLD epoch (epochId was already incremented by rotatePendingEpoch)
    const epoch: uint64 = this.epochId.value - 1;
    const epochBoxKey: uint64 = epoch / EPOCHS_PER_BOX;
    const index: uint64 = epoch % EPOCHS_PER_BOX;

    const epochBox = this.epochBoxes(epochBoxKey);
    epochBox.create();

    epochBox.value[index] = this.currentRoot();

    // Reset committed index for new epoch
    this.nextCommittedLeafTreeIndex.value = 0;
  }

  protected commitEpochSentinel(): void {
    assert(
      this.nextCommittedLeafTreeIndex.value === 0,
      "sentinel already committed",
    );

    ensureBudget(MIMC_OPCODE_COST);
    const sentinelLeaf = new Uint256(this.epochId.value);
    const tree = clone(this.zeroHashes.value);
    const { root } = calculateRootAndSubtree(sentinelLeaf, 0, tree);

    assert(this.pendingLeaves(sentinelLeaf).delete(), "sentinel not pending");
    this.lastCommittedLeaf.value = sentinelLeaf;
    this.addRoot(root);
    this.nextCommittedLeafTreeIndex.value = 1;
  }

  protected rotatePendingEpoch(): void {
    assert(
      this.indexNearMax(this.nextPendingLeafTreeIndex.value),
      "tree not near max",
    );
    this.epochId.value += 1;
    this.epochEndedOnIndex.value = this.nextPendingLeafTreeIndex.value;
    this.nextPendingLeafTreeIndex.value = 0;
    const sentinelLeaf = new Uint256(this.epochId.value);
    this.addPendingLeaf(sentinelLeaf);
  }

  protected currentRoot(): Uint256 {
    return this.rootCache.value[(this.rootCounter.value - 1) % ROOT_CACHE_SIZE];
  }

  protected addPendingLeaf(leafHash: Uint256): uint64 {
    assert(!this.pendingLeaves(leafHash).exists, "leaf already pending");
    assert(
      !this.indexNearMax(this.nextPendingLeafTreeIndex.value),
      "tree full, call rotatePendingEpoch",
    );
    const leafIndex = this.nextPendingLeafTreeIndex.value;
    this.pendingLeaves(leafHash).value = leafIndex;
    this.nextPendingLeafTreeIndex.value += 1;
    return leafIndex;
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

  protected commitLeafWithLsig(
    commitmentLsig: gtxn.Transaction,
    args: CommitLeafArgs,
  ): void {
    const pendingLeaf = this.pendingLeaves(args.newLeaf);
    assert(pendingLeaf.exists, "leaf not pending");
    assert(pendingLeaf.value === args.newLeafIndex, "invalid newLeafIndex");
    assert(
      pendingLeaf.value === this.nextCommittedLeafTreeIndex.value,
      "leaf commitment out of order",
    );

    assert(
      commitmentLsig.sender === this.commitmentLsigAddr.value,
      "invalid commitment Lsig",
    );

    assert(
      args.lastLeaf === this.lastCommittedLeaf.value,
      "previous leaf mismatch",
    );

    assert(
      args.newLeafIndex === this.nextCommittedLeafTreeIndex.value,
      "unexpected leaf index",
    );

    assert(this.currentRoot() === args.currentRoot, "current root mismatch");
    this.commitLeafRoot(args.newLeaf, args.newRoot);
  }

  private commitLeafRoot(newLeaf: Uint256, root: Uint256): void {
    assert(this.pendingLeaves(newLeaf).delete(), "leaf not pending");
    this.lastCommittedLeaf.value = newLeaf;
    this.addRoot(root);
    this.nextCommittedLeafTreeIndex.value += 1;

    if (
      this.nextCommittedLeafTreeIndex.value === this.epochEndedOnIndex.value
    ) {
      this.sealEpoch();
    }
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
