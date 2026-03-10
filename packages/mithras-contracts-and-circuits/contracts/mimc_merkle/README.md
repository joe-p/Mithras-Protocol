# MiMC Merkle Contract

This contract implements a merkle tree with the MiMC hash function. The most straightforward approach to a merkle tree in an Algorand app is to simply due the hashing when the leaf is added. This approach, however, can be very expensive due to the cost of the MiMC opcode. The total cost can be calculated as `1110 * TREE_DEPTH`. For a tree depth of 20, this comes out to 22,000. That much opcode budget in an app results in 30 app calls and that's not accounting for all the other opcodes executed in the app. This results in any application that uses the merkle tree to be 30x more expensive than a regular app call. If we can find a way to offload the computation in an lsig, however, it can be much cheaper. Below is a breakdown of how we are able to achive this.

## Problems & Solutions

### First Problem: Logic Sigs Are Stateless

When doing all tree construction/verification inside the application we can easily store the current root and frontier of the tree in the application state. This allows users to call the app with only their leaf and the app can easily append it. With logic sigs, however, we cannot directly store or access any application state.

#### Solution: Verify Tree Transition in Application

While we can't directly read the frontier from application state, we can rebuild it off-chain and then verify the following in the application:

```typescript
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
```

First we verify that the `currentRoot` is correct for the given `currentFrontier` and `lastLeaf`. This ensures that the tree state is correct before we add the new leaf. Next we verify that the `newRoot` is correct for the given `currentFrontier`, `lastLeaf`, `newLeaf`, and `newLeafIndex`. This ensures that the new leaf is being added correctly to the tree. If both of these checks pass, then we know that the tree transition from `currentRoot` to `newRoot` is valid and we can update the tree state in the application.

The application keeps track of `currentRoot` and `lastLeaf` in its state. The frontier is not stored in the application state but is instead reconstructed off-chain by users when they want to commit a new leaf.

### Second Problem: Race Conditions

Since the logic sig is stateless, multiple users could potentially try to commit a new leaf at the same time with the same `currentRoot` and `lastLeaf`. The transaction that gets evaluated first in the block will succeed with all subsequent transactions failing since their `currentRoot` and `lastLeaf` will no longer be correct. This effectively rate limits the number of leaf commitments to 1 per block which is not ideal.

#### Solution: Decouple Leaf Additions and Tree Updates

To solve this problem, we can decouple the leaf addition from the tree update. Rather than having users pass their new leaf to the contract and update the tree in the same transaction, we can decouple these actions. The first transaction will assign the add the leaf to a "pending" queue in the application state. Once added to the queue, a index will be assigned to that leaf. The second transaction will then take the leaf from the "pending" queue and add it to the tree via the logic sig. This now allows for multiple new leafs to be added to the "pending" queue in the same block without any race conditions.

The trade-off of this solution is that there may be a one round delay between when a leaf is added and when it is actually committed to the tree. Since the new index is not known until the round is confirmed, these actions cannot be done atomically. It is, however, possible for a user to attempt to "guess" which index they will get assigned and optimistically try to commit their leaf in the same round. If they guess wrong, their transaction(s) will simply fail and they can try again in the next round with the correct index. In practice this only really works if they are the only user adding a leaf in that round because different nodes in the network might receive transactions in different orders.

### Third Problem: Uncommitted Leaves

A malicious user could add a leaf to the "pending" queue and then never commit it to the tree. This would result in a denial of service attack where the tree cannot be updated with new leafs because there is always an uncommitted leaf at the front of the queue.

#### Solution: Incentivize Tree Updates

To solve this problem, we can attach an incentive to each pending leaf that gets paid out to the user that successfully commits the leaf to the tree. This creates a financial incentive for users to commit pending leafs to the tree and keeps the system moving forward. The incentive can be funded by the user when they add their leaf to the pending queue and then paid out by the application when the leaf is successfully committed to the tree.

### Fourth Problem: Fee Increases

When a user adds their leaf to the pending queue they specify how much incentive they want to add. The contract can enforce the fee is at least the min fee to perform the commitment, but it may be possible for fees to increase between when the leaf is added and when it is committed to the tree. If the fee increases too much, it may no longer be profitable for anyone to commit the leaf to the tree and the system could get stuck.

#### Solution: Mutable Incentives

Once a pending leaf is added to the queue, any user can add additional ALGO to the incentive for that leaf. This user *could* be the one that originally added the leaf, but any user that has an interest in "unsticking" the system can add to the incentive. This allows the system to adapt to fee changes and keeps it moving forward even in times of high congestion when fees are more likely to spike.

## Front-Running Commitments

It should be noted that front-running is possible for leaf commitments. In most cases, however, the incentive will just be enough to cover the cost of fees so there is little reason for front running to occur. Because of this, the protocol does not do anything to actively prevent front-running.
