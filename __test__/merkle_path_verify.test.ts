import circom_tester from "circom_tester";
import { describe, it, beforeAll, expect } from "vitest";
const wasm_tester = circom_tester.wasm;

describe("Merkle Path Verify Circuit Tests", () => {
  let circuit: any;

  beforeAll(async () => {
    circuit = await wasm_tester("circuits/merkle_path_verify.circom", {
      prime: "bls12381",
      recompile: true,
    });
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
});

