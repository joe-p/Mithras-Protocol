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
  itxn,
  Global,
  assertMatch,
} from "@algorandfoundation/algorand-typescript";
import { TREE_DEPTH } from "../src/constants";
import {
  decodeArc4,
  Uint256,
} from "@algorandfoundation/algorand-typescript/arc4";

const ZERO_HASHES =
  TemplateVar<FixedArray<Uint256, typeof TREE_DEPTH>>("ZERO_HASHES");

const ROOT_CACHE_SIZE = 50;

// Base cost for mimc is 10 uALGO, and each bytes<32> costs 550 uALGO
const MIMC_OPCODE_COST = 1110 * TREE_DEPTH;

@contract({ avmVersion: 11 })
export class MimcMerkle extends Contract {
  /*************************************************************************************************
   * Global State
   *************************************************************************************************/

  /**
   * Keeps track of the number of roots stored in the root cache, and to determine the index to store the next root
   */
  rootCounter = GlobalState<uint64>({ key: "c" });

  /**
   * The next index to use when committing a pending leaf to the tree.
   */
  nextCommittedLeafTreeIndex = GlobalState<uint64>({ key: "i" });

  /**
   * The next index to use for the next pending leaf. Should be reset to 0 when rotating epoch.
   */
  nextPendingLeafTreeIndex = GlobalState<uint64>({ key: "p" });

  /**
   * An epoch is the identifier for a root commitment period. When the epoch is rotated, a new sentinel leaf is added
   * to the tree with the new epochId, and the previous epochId is sealed with the last root committed in that epoch.
   */
  epochId = GlobalState<uint64>({ key: "e" });

  /**
   * The last leaf that was committed to the tree. This is needed for committing a new leaf to ensure order of leaf
   * commitments
   */
  lastCommittedLeaf = GlobalState<Uint256>({ key: "ll" });

  /**
   * The address of the logic signature that does the computation for committing a leaf to the tree
   */
  commitmentLsigAddr = GlobalState<Account>({ key: "a" });

  /**
   * The index at which the past epoch ended. This is needed to know when to seal an epoch, which happens when the
   * next committed leaf index reaches this value
   */
  epochEndedOnIndex = GlobalState<uint64>({ key: "e" });

  /*************************************************************************************************
   * Boxes
   *************************************************************************************************/

  /**
   * A cache of recent roots to validate against. This helps prevent race conditions for when a circuit proves a
   * leaf against a root that has since changed within the block
   */
  rootCache = Box<FixedArray<Uint256, typeof ROOT_CACHE_SIZE>>({ key: "r" });

  /**
   * When an epoch is sealed, the final root for that epoch is stored in epochRoots under the epochId.
   */
  epochRoots = BoxMap<uint64, Uint256>({
    keyPrefix: "e",
  });

  /**
   * Leaves that have been added but not yet committed to the tree
   *
   * The value is the leaf index for the pending leaf and the incentive amount for committing that leaf
   */
  pendingLeaves = BoxMap<Uint256, { index: uint64; incentive: uint64 }>({
    keyPrefix: "p",
  });

  protected bootstrap(commitLeafLsig: Account): void {
    this.commitmentLsigAddr.value = commitLeafLsig;
    ensureBudget(MIMC_OPCODE_COST);

    this.epochId.value = 0;
    this.rootCache.create();

    const sentinelLeaf = new Uint256(this.epochId.value);
    this.addPendingLeaf(sentinelLeaf, 0);

    const { root } = calculateRootAndSubtree(sentinelLeaf, 0, ZERO_HASHES);
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
    this.epochRoots(epoch).value = this.currentRoot();

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
    const { root } = calculateRootAndSubtree(sentinelLeaf, 0, ZERO_HASHES);

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
    this.addPendingLeaf(sentinelLeaf, 0);
  }

  protected currentRoot(): Uint256 {
    return this.rootCache.value[(this.rootCounter.value - 1) % ROOT_CACHE_SIZE];
  }

  protected addPendingLeaf(leafHash: Uint256, incentive: uint64): uint64 {
    assert(!this.pendingLeaves(leafHash).exists, "leaf already pending");
    assert(
      !this.indexNearMax(this.nextPendingLeafTreeIndex.value),
      "tree full, call rotatePendingEpoch",
    );
    const leafIndex = this.nextPendingLeafTreeIndex.value;
    this.pendingLeaves(leafHash).value = { index: leafIndex, incentive };
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
    return this.epochRoots(epochId).value === root;
  }

  protected addRoot(rootHash: Uint256): void {
    const index: uint64 = this.rootCounter.value % ROOT_CACHE_SIZE;
    this.rootCache.value[index] = rootHash;

    this.rootCounter.value += 1;
  }

  protected addIncentive(payment: gtxn.PaymentTxn, leafHash: Uint256): uint64 {
    assertMatch(
      payment,
      { receiver: Global.currentApplicationAddress },
      "incentive payment must be sent to the application address",
    );

    const pendingLeaf = this.pendingLeaves(leafHash);
    assert(pendingLeaf.exists, "leaf not pending");

    const incentive: uint64 = pendingLeaf.value.incentive + payment.amount;
    this.pendingLeaves(leafHash).value = {
      index: pendingLeaf.value.index,
      incentive,
    };

    return incentive;
  }

  protected commitLeafWithLsig(
    commitmentLsig: gtxn.Transaction,
    args: CommitLeafArgs,
  ): void {
    const pendingLeaf = this.pendingLeaves(args.newLeaf);
    assert(pendingLeaf.exists, "leaf not pending");
    const pendingLeafIndex = pendingLeaf.value.index;
    assert(pendingLeafIndex === args.newLeafIndex, "invalid newLeafIndex");
    assert(
      pendingLeafIndex === this.nextCommittedLeafTreeIndex.value,
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

    if (pendingLeaf.value.incentive > 0) {
      itxn
        .payment({
          receiver: Txn.sender,
          amount: pendingLeaf.value.incentive,
        })
        .submit();
    }
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
  let left: Uint256;
  let right: Uint256;
  let currentHash = leaf;

  for (let i: uint64 = 0; i < TREE_DEPTH; i++) {
    if ((index & 1) === 0) {
      subtree[i] = currentHash;
      left = currentHash;
      right = ZERO_HASHES[i];
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
