import { describe, it, expect, beforeAll } from "vitest";
import { microAlgos } from "@algorandfoundation/algokit-utils";
import {
  MimcCalculator,
  MerkleTestHelpers,
  TestDataBuilder,
} from "./utils/test-utils";
import { MimcMerkleHelper } from "./utils/contract-helpers";
import { TREE_DEPTH } from "../src/constants";

// These tests validate epoch rollover and sealed root verification

describe("Merkle rollover + sealed roots", () => {
  let mimc: MimcCalculator;

  beforeAll(async () => {
    mimc = await MimcCalculator.create();
  });

  it("seals current epoch and validates sealed root; resets to empty root", async () => {
    const appClient = await MimcMerkleHelper.deployContract();

    // Add a single leaf and compute the expected root using zero path
    const leaf = TestDataBuilder.createTestLeaf(0xabcddcba);
    await MimcMerkleHelper.addLeaf(
      appClient,
      MerkleTestHelpers.bytesToBigInt(leaf),
    );

    const { zeroHashes } = await MimcMerkleHelper.getContractState(appClient);

    const pathElements: bigint[] = [];
    const pathSelectors: number[] = [];
    for (let i = 0; i < TREE_DEPTH; i++) {
      pathElements.push(zeroHashes[i]);
      pathSelectors.push(0);
    }
    const rootBig = await mimc.calculateMerkleRoot(
      MerkleTestHelpers.bytesToBigInt(leaf),
      pathElements,
      pathSelectors,
    );

    // Rollover (seal epoch 0)
    // Extra fee for box write + ops
    await MimcMerkleHelper.sealAndRotate(appClient);

    // Validate sealed root for epoch 0
    const sealedOk = await MimcMerkleHelper.isValidSealedRoot(
      appClient,
      0n,
      rootBig,
    );
    expect(sealedOk).toBe(true);

    // After rotate, empty-root must be in recent cache
    const emptyRootBytes = zeroHashes[TREE_DEPTH - 1];
    const { return: emptyOk } = await appClient.send.isValidRootTest({
      args: { root: emptyRootBytes },
    });
    expect(emptyOk).toBe(true);

    // Add another leaf in new epoch (epoch 1)
    const leaf2 = TestDataBuilder.createTestLeaf(0x01020304);
    await MimcMerkleHelper.addLeaf(
      appClient,
      MerkleTestHelpers.bytesToBigInt(leaf2),
    );
    const { zeroHashes: zero2 } =
      await MimcMerkleHelper.getContractState(appClient);

    // Compute the expected new root for leaf2
    const pe2: bigint[] = [];
    const pi2: number[] = [];
    for (let i = 0; i < TREE_DEPTH; i++) {
      pe2.push(zero2[i]);
      pi2.push(0);
    }
    const root2Big = await mimc.calculateMerkleRoot(
      MerkleTestHelpers.bytesToBigInt(leaf2),
      pe2,
      pi2,
    );
    const root2 = root2Big;

    const { return: isValid2 } = await appClient.send.isValidRootTest({
      args: { root: root2 },
    });
    expect(isValid2).toBe(true);
  });
});
