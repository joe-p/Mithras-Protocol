import { describe, it, expect, beforeAll } from "vitest";
import { microAlgos } from "@algorandfoundation/algokit-utils";
import {
  MimcCalculator,
  MerkleTestHelpers,
  TestDataBuilder,
} from "./utils/test-utils";
import { MimcMerkleHelper } from "./utils/contract-helpers";

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
    await MimcMerkleHelper.addLeaf(appClient, leaf);

    const { zeroHashes } = await MimcMerkleHelper.getContractState(appClient);

    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    for (let i = 0; i < 32; i++) {
      pathElements.push(MerkleTestHelpers.bytesToBigInt(zeroHashes[i]));
      pathIndices.push(0);
    }
    const rootBig = await mimc.calculateMerkleRoot(
      MerkleTestHelpers.bytesToBigInt(leaf),
      pathElements,
      pathIndices,
    );
    const rootBytes = MerkleTestHelpers.bigIntToBytes(rootBig);

    // Rollover (seal epoch 0)
    // Extra fee for box write + ops
    await MimcMerkleHelper.sealAndRotate(appClient);

    // Validate sealed root for epoch 0
    const sealedOk = await MimcMerkleHelper.isValidSealedRoot(
      appClient,
      0n,
      rootBytes,
    );
    expect(sealedOk).toBe(true);

    // After rotate, empty-root must be in recent cache
    const emptyRootBytes = zeroHashes[31];
    const { return: emptyOk } = await appClient.send.isValidRoot({
      args: { root: emptyRootBytes },
    });
    expect(emptyOk).toBe(true);

    // Add another leaf in new epoch (epoch 1)
    const leaf2 = TestDataBuilder.createTestLeaf(0x01020304);
    await MimcMerkleHelper.addLeaf(appClient, leaf2);
    const { zeroHashes: zero2 } =
      await MimcMerkleHelper.getContractState(appClient);

    // Compute the expected new root for leaf2
    const pe2: bigint[] = [];
    const pi2: number[] = [];
    for (let i = 0; i < 32; i++) {
      pe2.push(MerkleTestHelpers.bytesToBigInt(zero2[i]));
      pi2.push(0);
    }
    const root2Big = await mimc.calculateMerkleRoot(
      MerkleTestHelpers.bytesToBigInt(leaf2),
      pe2,
      pi2,
    );
    const root2 = MerkleTestHelpers.bigIntToBytes(root2Big);

    const { return: isValid2 } = await appClient.send.isValidRoot({
      args: { root: root2 },
    });
    expect(isValid2).toBe(true);
  });
});
