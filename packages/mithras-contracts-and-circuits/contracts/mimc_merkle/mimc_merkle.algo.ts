import {
  assert,
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
  bytes,
} from "@algorandfoundation/algorand-typescript";
import { TREE_DEPTH } from "../../src/constants";
import {
  decodeArc4,
  Uint256,
} from "@algorandfoundation/algorand-typescript/arc4";

const ZERO_HASHES =
  TemplateVar<FixedArray<Uint256, typeof TREE_DEPTH>>("ZERO_HASHES");

const ROOT_CACHE_ROUNDS = 1000;

// Base cost for mimc is 10 uALGO, and each bytes<32> costs 550 uALGO
const MIMC_OPCODE_COST = 1110 * TREE_DEPTH;

@contract({ avmVersion: 11 })
export class MimcMerkle extends Contract {
  /*************************************************************************************************
   * Global State
   *************************************************************************************************/

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

  /**
   * The current root of the tree. This is needed to validate proofs against the current tree state
   * and to ensure the order of leaf commitments
   */
  currentRoot = GlobalState<Uint256>({ key: "r" });

  /*************************************************************************************************
   * Boxes
   *************************************************************************************************/

  /**
   * A cache of recent roots to validate against. This helps prevent race conditions for when a circuit proves a
   * leaf against a root that has since changed within the block. The value stored is the round when the root was
   * added to the cache, which is used to ensure roots are only removed from the cache after a certain number of
   * rounds have passed
   */
  rootCache = BoxMap<Uint256, uint64>({ keyPrefix: "r" });

  /**
   * When an epoch is sealed, the final root for that epoch is stored in epochRoots under the epochId.
   */
  epochRoots = BoxMap<Uint256, bytes<0>>({
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

    // TODO: determine budget needed here
    ensureBudget(MIMC_OPCODE_COST + 7000);

    this.epochId.value = 0;
    this.nextPendingLeafTreeIndex.value = 0;

    const sentinelLeaf = new Uint256(this.epochId.value);
    this.addPendingLeaf(sentinelLeaf, 0);

    const { root } = calculateRootAndFrontier(sentinelLeaf, 0, ZERO_HASHES);
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

    this.epochRoots(this.currentRoot.value).create();

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
    const { root } = calculateRootAndFrontier(sentinelLeaf, 0, ZERO_HASHES);

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
    return (
      root === this.currentRoot.value ||
      this.rootCache(root).exists ||
      this.epochRoots(root).exists
    );
  }

  protected addRoot(rootHash: Uint256): void {
    this.rootCache(rootHash).create();
    this.currentRoot.value = rootHash;
  }

  protected removeRootFromCache(root: Uint256): void {
    assert(
      Global.round - this.rootCache(root).value < ROOT_CACHE_ROUNDS,
      "cannot remove root from cache in the same round it was added",
    );

    const preMbr = Global.currentApplicationAddress.minBalance;
    this.rootCache(root).delete();
    const postMbr = Global.currentApplicationAddress.minBalance;

    itxn
      .payment({
        receiver: Txn.sender,
        amount: preMbr - postMbr,
      })
      .submit();
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

    assert(
      this.currentRoot.value === args.currentRoot,
      "current root mismatch",
    );

    if (pendingLeaf.value.incentive > 0) {
      itxn
        .payment({
          receiver: Txn.sender,
          amount: pendingLeaf.value.incentive,
        })
        .submit();
    }

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

export type Frontier = FixedArray<Uint256, typeof TREE_DEPTH>;

/**
 * The arguments needed for the commitment logic signature to commit a leaf to the tree
 * These are verified by the application
 *
 * size breakdown:
 *  - newLeaf: 32 bytes
 *  - lastLeaf: 32 + 32 = 64 bytes
 *  - newLeafIndex: 64 + 8 = 72 bytes
 *  - currentFrontier: 72 + (32 * TREE_DEPTH) = 72 + (32 * 20) = 712 bytes
 *  - currentRoot: 712 + 32 = 744 bytes
 *  - newRoot: 744 + 32 = 776 bytes
 */
export type CommitLeafArgs = {
  /** The frontier before adding the new leaf. This is needed to calculate the new root and to ensure the proof is valid for the current tree state */
  currentFrontier: Frontier;
  /** The last leaf that was committed to the tree. This is needed to ensure the order of leaf commitments */
  lastLeaf: Uint256;
  /** The current root of the tree. This is needed to ensure the proof is valid for the current tree state */
  currentRoot: Uint256;
  /** The new leaf we are appending to the tree */
  newLeaf: Uint256;
  /** The index of the new leaf being committed. This is needed to ensure the order of leaf commitments and to calculate the new root */
  newLeafIndex: uint64;
  /** The new root of the tree after adding the new leaf. This is needed to ensure the proof is valid and to update the tree state in the application */
  newRoot: Uint256;
};

export class CommitLeaf extends LogicSig {
  program(): boolean {
    const appl = gtxn.ApplicationCallTxn(Txn.groupIndex + 1);
    const args = decodeArc4<CommitLeafArgs>(appl.appArgs(1));

    const { root: currentRoot, frontier: currentFrontier } =
      calculateRootAndFrontier(
        args.lastLeaf,
        args.newLeafIndex - 1,
        args.currentFrontier,
      );
    assert(currentRoot === args.currentRoot, "old root mismatch");

    const { root: newRoot } = calculateRootAndFrontier(
      args.newLeaf,
      args.newLeafIndex,
      currentFrontier,
    );

    assert(newRoot === args.newRoot, "new root mismatch");

    return true;
  }
}

function calculateRootAndFrontier(
  leaf: Uint256,
  index: uint64,
  frontier: Frontier,
): { root: Uint256; frontier: Frontier } {
  let left: Uint256;
  let right: Uint256;
  let currentHash = leaf;

  for (let i: uint64 = 0; i < TREE_DEPTH; i++) {
    if ((index & 1) === 0) {
      frontier[i] = currentHash;
      left = currentHash;
      right = ZERO_HASHES[i];
    } else {
      left = frontier[i];
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

  return { root: currentHash, frontier };
}
