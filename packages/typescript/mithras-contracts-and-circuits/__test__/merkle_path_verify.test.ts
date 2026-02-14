import { describe, it, beforeAll, expect } from "vitest";
import {
  CircuitTester,
  MimcCalculator,
  MerkleTestHelpers,
  TestDataBuilder,
} from "./utils/test-utils";
import { MimcMerkleHelper } from "./utils/contract-helpers";
import { TREE_DEPTH } from "../src/constants";

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
    const pathSelectors = MerkleTestHelpers.createDefaultPathSelectors();

    pathElements[0] = 987654321n;
    pathElements[1] = 555666777n;

    const root = await mimcCalculator.calculateMerkleRoot(
      leaf,
      pathElements,
      pathSelectors,
    );
    const input = TestDataBuilder.createMerklePathInput(
      leaf,
      pathElements,
      pathSelectors,
    );

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
    expect(witness[1]).toBe(root);
  });

  it("should verify path with right branches", async () => {
    const leaf = 111222333n;
    const pathElements = MerkleTestHelpers.createDefaultPathElements();
    const pathSelectors = MerkleTestHelpers.createDefaultPathSelectors();

    pathElements[0] = 444555666n;
    pathSelectors[0] = 1;

    const root = await mimcCalculator.calculateMerkleRoot(
      leaf,
      pathElements,
      pathSelectors,
    );
    const input = TestDataBuilder.createMerklePathInput(
      leaf,
      pathElements,
      pathSelectors,
    );

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
    expect(witness[1]).toBe(root);
  });

  it("should handle mixed path directions", async () => {
    const leaf = 777888999n;
    const pathElements = MerkleTestHelpers.createDefaultPathElements();
    const pathSelectors = MerkleTestHelpers.createDefaultPathSelectors();

    pathElements[0] = 111n;
    pathElements[1] = 222n;
    pathElements[2] = 333n;
    pathSelectors[1] = 1;

    const root = await mimcCalculator.calculateMerkleRoot(
      leaf,
      pathElements,
      pathSelectors,
    );
    const input = TestDataBuilder.createMerklePathInput(
      leaf,
      pathElements,
      pathSelectors,
    );

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
    expect(witness[1]).toBe(root);
  });

  it("should generate root with contract and verify with circuit - single leaf", async () => {
    const appClient = await MimcMerkleHelper.deployContract();

    const leafHash = new Uint8Array(32);
    leafHash.set([0x12, 0x34, 0x56, 0x78], 0);

    await MimcMerkleHelper.addLeaf(appClient, leafHash);
    const { zeroHashes } = await MimcMerkleHelper.getContractState(appClient);

    const leaf = MerkleTestHelpers.bytesToBigInt(leafHash);
    const pathElements: bigint[] = [];
    const pathSelectors: number[] = [];

    for (let i = 0; i < TREE_DEPTH; i++) {
      pathElements.push(MerkleTestHelpers.bytesToBigInt(zeroHashes[i]));
      pathSelectors.push(0);
    }

    const root = await mimcCalculator.calculateMerkleRoot(
      leaf,
      pathElements,
      pathSelectors,
    );
    const input = TestDataBuilder.createMerklePathInput(
      leaf,
      pathElements,
      pathSelectors,
    );

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
    expect(witness[1]).toBe(root);
  });

  it("should generate root with contract and verify with circuit - multiple leaves", async () => {
    const appClient = await MimcMerkleHelper.deployContract();

    const leaves = [
      TestDataBuilder.createTestLeaf(0x11223344),
      TestDataBuilder.createTestLeaf(0x55667788),
      TestDataBuilder.createTestLeaf(0x99aabbcc),
    ];

    for (const leaf of leaves) {
      await MimcMerkleHelper.addLeaf(appClient, leaf);
    }

    const { subtree, zeroHashes } =
      await MimcMerkleHelper.getContractState(appClient);

    const leafToVerify = leaves[1];
    const leafIndex = 1;

    const pathElements: bigint[] = [];
    const pathSelectors: number[] = [];

    let index = leafIndex;
    for (let level = 0; level < TREE_DEPTH; level++) {
      if (level === 0) {
        pathElements.push(MerkleTestHelpers.bytesToBigInt(subtree[0]));
        pathSelectors.push(1);
      } else {
        pathElements.push(MerkleTestHelpers.bytesToBigInt(zeroHashes[level]));
        pathSelectors.push(0);
      }
      index >>= 1;
    }

    const leaf = MerkleTestHelpers.bytesToBigInt(leafToVerify);
    const root = await mimcCalculator.calculateMerkleRoot(
      leaf,
      pathElements,
      pathSelectors,
    );
    const input = TestDataBuilder.createMerklePathInput(
      leaf,
      pathElements,
      pathSelectors,
    );

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
    expect(witness[1]).toBe(root);
  });

  it("should verify contract-generated root using isValidRoot", async () => {
    const appClient = await MimcMerkleHelper.deployContract();

    const leafHash = TestDataBuilder.createTestLeaf(0xdeadbeef);

    await MimcMerkleHelper.addLeaf(appClient, leafHash);
    const { zeroHashes } = await MimcMerkleHelper.getContractState(appClient);

    const leaf = MerkleTestHelpers.bytesToBigInt(leafHash);
    const pathElements: bigint[] = [];
    const pathSelectors = MerkleTestHelpers.createDefaultPathSelectors();

    for (let i = 0; i < TREE_DEPTH; i++) {
      pathElements.push(MerkleTestHelpers.bytesToBigInt(zeroHashes[i]));
    }

    const root = await mimcCalculator.calculateMerkleRoot(
      leaf,
      pathElements,
      pathSelectors,
    );
    const computedRootBytes = MerkleTestHelpers.bigIntToBytes(root);

    const isValid = await MimcMerkleHelper.verifyRoot(
      appClient,
      computedRootBytes,
    );
    expect(isValid).toBe(true);

    const input = TestDataBuilder.createMerklePathInput(
      leaf,
      pathElements,
      pathSelectors,
    );
    await MerkleTestHelpers.verifyCircuitWithInput(circuit, input);
  });
});
