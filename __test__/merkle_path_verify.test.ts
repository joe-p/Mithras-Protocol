import circom_tester from "circom_tester";
import { describe, it, beforeAll, expect } from "vitest";
import { AlgorandClient } from "@algorandfoundation/algokit-utils/types/algorand-client";
import { microAlgos } from "@algorandfoundation/algokit-utils";
import {
  MimcMerkleContractFactory,
  MimcMerkleContractClient,
} from "../contracts/clients/MimcMerkleContract";

const wasm_tester = circom_tester.wasm;

async function getAppClient() {
  const algorand = AlgorandClient.defaultLocalNet();
  const factory = new MimcMerkleContractFactory({
    algorand,
    defaultSender: await algorand.account.localNetDispenser(),
  });

  const { appClient } = await factory.deploy({
    appName: `mimc-merkle-${Math.random().toString(36).substring(2, 15)}`,
  });

  await algorand.account.ensureFundedFromEnvironment(
    appClient.appAddress,
    microAlgos(1567900),
  );

  await appClient.send.bootstrap({
    args: {},
    extraFee: microAlgos(256 * 1000),
  });

  return appClient;
}

async function addLeaf(
  appClient: MimcMerkleContractClient,
  leafHash: Uint8Array,
) {
  await appClient.send.addLeaf({
    args: { leafHash },
    extraFee: microAlgos(256 * 1000),
  });
}

describe("Merkle Path Verify Circuit Tests", () => {
  let circuit: any;
  let algorand: AlgorandClient;

  beforeAll(async () => {
    circuit = await wasm_tester("circuits/merkle_path_verify.circom", {
      prime: "bls12381",
      recompile: true,
    });

    algorand = AlgorandClient.defaultLocalNet();
  });

  it("should verify a valid merkle path", async () => {
    const leaf = 123456789n;
    const pathElements = new Array(32).fill(0n);
    const pathIndices = new Array(32).fill(0);

    pathElements[0] = 987654321n;
    pathElements[1] = 555666777n;

    const input = {
      leaf,
      pathElements,
      pathIndices,
      root: 0n,
    };

    const mimcTester = await wasm_tester("__test__/circuits/mimc.circom", {
      prime: "bls12381",
      recompile: true,
    });

    const level1 = await mimcTester.calculateWitness({
      msgs: [leaf, pathElements[0]],
    });
    const level1Hash = level1[1];

    const level2 = await mimcTester.calculateWitness({
      msgs: [level1Hash, pathElements[1]],
    });
    const level2Hash = level2[1];

    let currentHash = level2Hash;
    for (let i = 2; i < 32; i++) {
      const nextLevel = await mimcTester.calculateWitness({
        msgs: [currentHash, pathElements[i]],
      });
      currentHash = nextLevel[1];
    }

    input.root = currentHash;

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it("should verify path with right branches", async () => {
    const leaf = 111222333n;
    const pathElements = new Array(32).fill(0n);
    const pathIndices = new Array(32).fill(0);

    pathElements[0] = 444555666n;
    pathIndices[0] = 1;

    const input = {
      leaf,
      pathElements,
      pathIndices,
      root: 0n,
    };

    const mimcTester = await wasm_tester("__test__/circuits/mimc.circom", {
      prime: "bls12381",
      recompile: true,
    });

    const level1 = await mimcTester.calculateWitness({
      msgs: [pathElements[0], leaf],
    });
    let currentHash = level1[1];

    for (let i = 1; i < 32; i++) {
      const nextLevel = await mimcTester.calculateWitness({
        msgs: [currentHash, pathElements[i]],
      });
      currentHash = nextLevel[1];
    }

    input.root = currentHash;

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it("should fail with invalid root", async () => {
    const leaf = 123456789n;
    const pathElements = new Array(32).fill(0n);
    const pathIndices = new Array(32).fill(0);

    const input = {
      leaf,
      pathElements,
      pathIndices,
      root: 999999999n,
    };

    await expect(async () => {
      const witness = await circuit.calculateWitness(input);
      await circuit.checkConstraints(witness);
    }).rejects.toThrow();
  });

  it("should handle mixed path directions", async () => {
    const leaf = 777888999n;
    const pathElements = new Array(32).fill(0n);
    const pathIndices = new Array(32).fill(0);

    pathElements[0] = 111n;
    pathElements[1] = 222n;
    pathElements[2] = 333n;
    pathIndices[1] = 1;

    const input = {
      leaf,
      pathElements,
      pathIndices,
      root: 0n,
    };

    const mimcTester = await wasm_tester("__test__/circuits/mimc.circom", {
      prime: "bls12381",
      recompile: true,
    });

    const level1 = await mimcTester.calculateWitness({
      msgs: [leaf, pathElements[0]],
    });

    const level2 = await mimcTester.calculateWitness({
      msgs: [pathElements[1], level1[1]],
    });

    const level3 = await mimcTester.calculateWitness({
      msgs: [level2[1], pathElements[2]],
    });

    let currentHash = level3[1];
    for (let i = 3; i < 32; i++) {
      const nextLevel = await mimcTester.calculateWitness({
        msgs: [currentHash, pathElements[i]],
      });
      currentHash = nextLevel[1];
    }

    input.root = currentHash;

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it("should generate root with contract and verify with circuit - single leaf", async () => {
    const appClient = await getAppClient();

    const leafHash = new Uint8Array(32);
    leafHash.set([0x12, 0x34, 0x56, 0x78], 0);

    await addLeaf(appClient, leafHash);

    const subtree = await appClient.state.box.subtree();
    const zeroHashes = await appClient.state.box.zeroHashes();

    if (!subtree || !zeroHashes) {
      throw new Error("Failed to get state from contract");
    }

    let currentHash = BigInt("0x" + Buffer.from(leafHash).toString("hex"));
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];

    for (let i = 0; i < 32; i++) {
      pathElements.push(
        BigInt("0x" + Buffer.from(zeroHashes[i]).toString("hex")),
      );
      pathIndices.push(0);
    }

    const mimcTester = await wasm_tester("__test__/circuits/mimc.circom", {
      prime: "bls12381",
      recompile: true,
    });

    for (let i = 0; i < 32; i++) {
      const left = i === 0 ? currentHash : currentHash;
      const right = pathElements[i];

      const result = await mimcTester.calculateWitness({
        msgs: [left, right],
      });
      currentHash = result[1];
    }

    const input = {
      leaf: BigInt("0x" + Buffer.from(leafHash).toString("hex")),
      pathElements,
      pathIndices,
      root: currentHash,
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it("should generate root with contract and verify with circuit - multiple leaves", async () => {
    const appClient = await getAppClient();

    const leaves = [new Uint8Array(32), new Uint8Array(32), new Uint8Array(32)];

    leaves[0].set([0x11, 0x22, 0x33, 0x44], 28);
    leaves[1].set([0x55, 0x66, 0x77, 0x88], 28);
    leaves[2].set([0x99, 0xaa, 0xbb, 0xcc], 28);

    for (const leaf of leaves) {
      await addLeaf(appClient, leaf);
    }

    const subtree = await appClient.state.box.subtree();
    const zeroHashes = await appClient.state.box.zeroHashes();

    if (!subtree || !zeroHashes) {
      throw new Error("Failed to get state from contract");
    }

    const leafToVerify = leaves[1];
    const leafIndex = 1;

    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];

    let index = leafIndex;
    for (let level = 0; level < 32; level++) {
      if (level === 0) {
        pathElements.push(
          BigInt("0x" + Buffer.from(subtree[0]).toString("hex")),
        );
        pathIndices.push(1);
      } else {
        pathElements.push(
          BigInt("0x" + Buffer.from(zeroHashes[level]).toString("hex")),
        );
        pathIndices.push(0);
      }
      index >>= 1;
    }

    const mimcTester = await wasm_tester("__test__/circuits/mimc.circom", {
      prime: "bls12381",
      recompile: true,
    });

    let currentHash = BigInt("0x" + Buffer.from(leafToVerify).toString("hex"));

    for (let i = 0; i < 32; i++) {
      let left, right;
      if (pathIndices[i] === 0) {
        left = currentHash;
        right = pathElements[i];
      } else {
        left = pathElements[i];
        right = currentHash;
      }

      const result = await mimcTester.calculateWitness({
        msgs: [left, right],
      });
      currentHash = result[1];
    }

    const input = {
      leaf: BigInt("0x" + Buffer.from(leafToVerify).toString("hex")),
      pathElements,
      pathIndices,
      root: currentHash,
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it("should verify contract-generated root using isValidRoot", async () => {
    const appClient = await getAppClient();

    const leafHash = new Uint8Array(32);
    leafHash.set([0xde, 0xad, 0xbe, 0xef], 28);

    await addLeaf(appClient, leafHash);

    const subtree = await appClient.state.box.subtree();
    const zeroHashes = await appClient.state.box.zeroHashes();

    if (!subtree || !zeroHashes) {
      throw new Error("Failed to get state from contract");
    }

    const mimcTester = await wasm_tester("__test__/circuits/mimc.circom", {
      prime: "bls12381",
      recompile: true,
    });

    let currentHash = BigInt("0x" + Buffer.from(leafHash).toString("hex"));

    for (let i = 0; i < 32; i++) {
      const result = await mimcTester.calculateWitness({
        msgs: [
          currentHash,
          BigInt("0x" + Buffer.from(zeroHashes[i]).toString("hex")),
        ],
      });
      currentHash = result[1];
    }

    const computedRootBytes = new Uint8Array(32);
    const rootHex = currentHash.toString(16).padStart(64, "0");
    for (let i = 0; i < 32; i++) {
      computedRootBytes[i] = parseInt(rootHex.substr(i * 2, 2), 16);
    }

    const { return: isValid } = await appClient.send.isValidRoot({
      args: { root: computedRootBytes },
    });

    expect(isValid).toBe(true);

    const pathElements = new Array(32).fill(0n);
    const pathIndices = new Array(32).fill(0);

    for (let i = 0; i < 32; i++) {
      pathElements[i] = BigInt(
        "0x" + Buffer.from(zeroHashes[i]).toString("hex"),
      );
    }

    const input = {
      leaf: BigInt("0x" + Buffer.from(leafHash).toString("hex")),
      pathElements,
      pathIndices,
      root: currentHash,
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });
});
