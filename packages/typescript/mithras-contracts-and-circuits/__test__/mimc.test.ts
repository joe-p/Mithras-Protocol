import { describe, it, beforeAll, expect } from "vitest";
import { MimcTestClient } from "./contracts/clients/MimcTest";
import { microAlgos } from "@algorandfoundation/algokit-utils";
import { CircuitTester, MimcInput, TestDataBuilder } from "./utils/test-utils";
import { MimcTestHelper } from "./utils/contract-helpers";

describe("MiMC Circuit Tests", () => {
  let circuit: any;
  let client: MimcTestClient;

  beforeAll(async () => {
    circuit = await CircuitTester.createMimcTester();
    client = await MimcTestHelper.deployContract();
  });

  it("should match AVM output", async () => {
    const args: MimcInput = TestDataBuilder.createMimcInput(13n, 37n);

    const avmResult = await client.send.mimcTest({
      args,
      extraFee: microAlgos(2000),
    });
    const witness = await circuit.calculateWitness(args);
    await circuit.checkConstraints(witness);

    await circuit.assertOut(witness, avmResult.return!);
  });

  it("should compute MiMC_MP_111 correctly", async () => {
    const input = TestDataBuilder.createMimcInput(123456789n, 1n);

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);

    const output = witness[1];
    expect(output).toBeDefined();
    expect(typeof output).toBe("bigint");
  });

  it("should produce deterministic output for same inputs", async () => {
    const input: MimcInput = TestDataBuilder.createMimcInput(1000n, 1n);

    const witness1 = await circuit.calculateWitness(input);
    const witness2 = await circuit.calculateWitness(input);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    expect(witness1[1]).toBe(witness2[1]);
  });

  it("should produce different outputs for different inputs", async () => {
    const input1: MimcInput = TestDataBuilder.createMimcInput(1000n, 1n);
    const input2: MimcInput = TestDataBuilder.createMimcInput(1001n, 1n);

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    expect(witness1[1]).not.toBe(witness2[1]);
  });

  it("should handle zero inputs", async () => {
    const input: MimcInput = TestDataBuilder.createMimcInput(0n, 1n);

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);

    const output = witness[1];
    expect(output).toBeDefined();
  });

  it("should handle large field elements", async () => {
    const input: MimcInput = TestDataBuilder.createMimcInput(
      21888242871839275222246405745257275088548364400416034343698204186575808495617n,
      1n,
    );

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);

    const output = witness[1];
    expect(output).toBeDefined();
  });
});
