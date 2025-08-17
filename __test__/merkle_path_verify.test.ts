import { describe, it, beforeAll, expect } from "vitest";
import {
  CircuitTester,
  MimcCalculator,
  MerkleTestHelpers,
  TestDataBuilder,
} from "./utils/test-utils";
import { MimcMerkleContractHelper } from "./utils/contract-helpers";

describe("Merkle Path Verify Circuit Tests", () => {
  let circuit: any;
  let mimcCalculator: MimcCalculator;

  beforeAll(async () => {
    circuit = await CircuitTester.createMerklePathTester();
    mimcCalculator = await MimcCalculator.create();
  });

  it("should verify a valid merkle path", async () => {
    const leaf = 123456789n;
    const pathElements = MerkleTestHelpers.createDefaultPathElements();
    const pathIndices = MerkleTestHelpers.createDefaultPathIndices();

    pathElements[0] = 987654321n;
    pathElements[1] = 555666777n;

    const root = await mimcCalculator.calculateMerkleRoot(
      leaf,
      pathElements,
      pathIndices,
    );
    const input = TestDataBuilder.createMerklePathInput(
      leaf,
      pathElements,
      pathIndices,
      root,
    );

    await MerkleTestHelpers.verifyCircuitWithInput(circuit, input);
  });

  it("should verify path with right branches", async () => {
    const leaf = 111222333n;
    const pathElements = MerkleTestHelpers.createDefaultPathElements();
    const pathIndices = MerkleTestHelpers.createDefaultPathIndices();

    pathElements[0] = 444555666n;
    pathIndices[0] = 1;

    const root = await mimcCalculator.calculateMerkleRoot(
      leaf,
      pathElements,
      pathIndices,
    );
    const input = TestDataBuilder.createMerklePathInput(
      leaf,
      pathElements,
      pathIndices,
      root,
    );

    await MerkleTestHelpers.verifyCircuitWithInput(circuit, input);
  });

  it("should fail with invalid root", async () => {
    const leaf = 123456789n;
    const pathElements = MerkleTestHelpers.createDefaultPathElements();
    const pathIndices = MerkleTestHelpers.createDefaultPathIndices();

    const input = TestDataBuilder.createMerklePathInput(
      leaf,
      pathElements,
      pathIndices,
      999999999n,
    );

    await expect(async () => {
      await MerkleTestHelpers.verifyCircuitWithInput(circuit, input);
    }).rejects.toThrow();
  });

  it("should handle mixed path directions", async () => {
    const leaf = 777888999n;
    const pathElements = MerkleTestHelpers.createDefaultPathElements();
    const pathIndices = MerkleTestHelpers.createDefaultPathIndices();

    pathElements[0] = 111n;
    pathElements[1] = 222n;
    pathElements[2] = 333n;
    pathIndices[1] = 1;

    const root = await mimcCalculator.calculateMerkleRoot(
      leaf,
      pathElements,
      pathIndices,
    );
    const input = TestDataBuilder.createMerklePathInput(
      leaf,
      pathElements,
      pathIndices,
      root,
    );

    await MerkleTestHelpers.verifyCircuitWithInput(circuit, input);
  });

  it("should generate root with contract and verify with circuit - single leaf", async () => {
    const appClient = await MimcMerkleContractHelper.deployContract();

    const leafHash = new Uint8Array(32);
    leafHash.set([0x12, 0x34, 0x56, 0x78], 0);

    await MimcMerkleContractHelper.addLeaf(appClient, leafHash);
    const { zeroHashes } =
      await MimcMerkleContractHelper.getContractState(appClient);

    const leaf = MerkleTestHelpers.bytesToBigInt(leafHash);
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];

    for (let i = 0; i < 32; i++) {
      pathElements.push(MerkleTestHelpers.bytesToBigInt(zeroHashes[i]));
      pathIndices.push(0);
    }

    const root = await mimcCalculator.calculateMerkleRoot(
      leaf,
      pathElements,
      pathIndices,
    );
    const input = TestDataBuilder.createMerklePathInput(
      leaf,
      pathElements,
      pathIndices,
      root,
    );

    await MerkleTestHelpers.verifyCircuitWithInput(circuit, input);
  });

  it("should generate root with contract and verify with circuit - multiple leaves", async () => {
    const appClient = await MimcMerkleContractHelper.deployContract();

    const leaves = [
      TestDataBuilder.createTestLeaf(0x11223344),
      TestDataBuilder.createTestLeaf(0x55667788),
      TestDataBuilder.createTestLeaf(0x99aabbcc),
    ];

    for (const leaf of leaves) {
      await MimcMerkleContractHelper.addLeaf(appClient, leaf);
    }

    const { subtree, zeroHashes } =
      await MimcMerkleContractHelper.getContractState(appClient);

    const leafToVerify = leaves[1];
    const leafIndex = 1;

    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];

    let index = leafIndex;
    for (let level = 0; level < 32; level++) {
      if (level === 0) {
        pathElements.push(MerkleTestHelpers.bytesToBigInt(subtree[0]));
        pathIndices.push(1);
      } else {
        pathElements.push(MerkleTestHelpers.bytesToBigInt(zeroHashes[level]));
        pathIndices.push(0);
      }
      index >>= 1;
    }

    const leaf = MerkleTestHelpers.bytesToBigInt(leafToVerify);
    const root = await mimcCalculator.calculateMerkleRoot(
      leaf,
      pathElements,
      pathIndices,
    );
    const input = TestDataBuilder.createMerklePathInput(
      leaf,
      pathElements,
      pathIndices,
      root,
    );

    await MerkleTestHelpers.verifyCircuitWithInput(circuit, input);
  });

  it("should verify contract-generated root using isValidRoot", async () => {
    const appClient = await MimcMerkleContractHelper.deployContract();

    const leafHash = TestDataBuilder.createTestLeaf(0xdeadbeef);

    await MimcMerkleContractHelper.addLeaf(appClient, leafHash);
    const { zeroHashes } =
      await MimcMerkleContractHelper.getContractState(appClient);

    const leaf = MerkleTestHelpers.bytesToBigInt(leafHash);
    const pathElements: bigint[] = [];
    const pathIndices = MerkleTestHelpers.createDefaultPathIndices();

    for (let i = 0; i < 32; i++) {
      pathElements.push(MerkleTestHelpers.bytesToBigInt(zeroHashes[i]));
    }

    const root = await mimcCalculator.calculateMerkleRoot(
      leaf,
      pathElements,
      pathIndices,
    );
    const computedRootBytes = MerkleTestHelpers.bigIntToBytes(root);

    const isValid = await MimcMerkleContractHelper.verifyRoot(
      appClient,
      computedRootBytes,
    );
    expect(isValid).toBe(true);

    const input = TestDataBuilder.createMerklePathInput(
      leaf,
      pathElements,
      pathIndices,
      root,
    );
    await MerkleTestHelpers.verifyCircuitWithInput(circuit, input);
  });
});
