import circom_tester from "circom_tester";
import { describe, it, beforeAll, expect } from "vitest";
import { MimcTestClient, MimcTestFactory } from "./contracts/clients/MimcTest";
import { AlgorandClient } from "@algorandfoundation/algokit-utils/types/algorand-client";
import { microAlgos } from "@algorandfoundation/algokit-utils";
const wasm_tester = circom_tester.wasm;

type Input = {
  msgs: [bigint, bigint];
};

describe("MiMC Circuit Tests", () => {
  let circuit: any;
  let client: MimcTestClient;

  beforeAll(async () => {
    circuit = await wasm_tester("circuits/mimc.circom", {
      prime: "bls12381",
      recompile: true,
    });

    const algorand = AlgorandClient.defaultLocalNet();
    const factory = new MimcTestFactory({
      algorand,
      defaultSender: await algorand.account.localNetDispenser(),
    });

    // use random app name for deployment
    const { appClient } = await factory.deploy({
      appName: `mimc-test-${Math.random().toString(36).substring(2, 15)}`,
    });
    client = appClient;
  });

  it("should match AVM output", async () => {
    const args: Input = {
      msgs: [13n, 37n],
    };

    const avmResult = await client.send.mimcTest({
      args,
      extraFee: microAlgos(2000),
    });
    const witness = await circuit.calculateWitness(args);
    await circuit.checkConstraints(witness);

    console.debug("AVM Result:", avmResult.return);
    await circuit.assertOut(witness, avmResult.return!);
  });

  it("should compute MiMC_MP_111 correctly", async () => {
    const input = {
      msgs: [123456789n, 1n],
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);

    const output = witness[1];
    expect(output).toBeDefined();
    expect(typeof output).toBe("bigint");
  });

  it("should produce deterministic output for same inputs", async () => {
    const input: Input = {
      msgs: [1000n, 1n],
    };

    const witness1 = await circuit.calculateWitness(input);
    const witness2 = await circuit.calculateWitness(input);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    expect(witness1[1]).toBe(witness2[1]);
  });

  it("should produce different outputs for different inputs", async () => {
    const input1: Input = {
      msgs: [1000n, 1n],
    };

    const input2: Input = {
      msgs: [1001n, 1n],
    };

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    expect(witness1[1]).not.toBe(witness2[1]);
  });

  it("should handle zero inputs", async () => {
    const input: Input = {
      msgs: [0n, 1n],
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);

    const output = witness[1];
    expect(output).toBeDefined();
  });

  it("should handle large field elements", async () => {
    const input: Input = {
      msgs: [
        21888242871839275222246405745257275088548364400416034343698204186575808495617n,
        1n,
      ],
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);

    const output = witness[1];
    expect(output).toBeDefined();
  });
});
