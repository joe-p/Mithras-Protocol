import circom_tester from "circom_tester";
import { describe, it, beforeAll, expect } from "vitest";
import { MimcTestClient, MimcTestFactory } from "./contracts/clients/MimcTest";
import { AlgorandClient } from "@algorandfoundation/algokit-utils/types/algorand-client";
const wasm_tester = circom_tester.wasm;

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

    const { appClient } = await factory.deploy();
    client = appClient;
  });

  it("should compute MiMC_MP_111 correctly", async () => {
    const input = {
      msg: "123456789",
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);

    const output = witness[1];
    expect(output).toBeDefined();
    expect(typeof output).toBe("bigint");
  });

  it("should produce deterministic output for same inputs", async () => {
    const input = {
      msg: "1000",
    };

    const witness1 = await circuit.calculateWitness(input);
    const witness2 = await circuit.calculateWitness(input);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    expect(witness1[1]).toBe(witness2[1]);
  });

  it("should produce different outputs for different inputs", async () => {
    const input1 = {
      msg: "1000",
    };

    const input2 = {
      msg: "1001",
    };

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    expect(witness1[1]).not.toBe(witness2[1]);
  });

  it("should handle zero inputs", async () => {
    const input = {
      msg: "0",
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);

    const output = witness[1];
    expect(output).toBeDefined();
  });

  it("should handle large field elements", async () => {
    const input = {
      msg: "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);

    const output = witness[1];
    expect(output).toBeDefined();
  });

  function bytesToBigInt(bytes: Uint8Array): bigint {
    let result = BigInt(0);
    for (let i = 0; i < bytes.length; i++) {
      result = (result << BigInt(8)) | BigInt(bytes[i]);
    }
    return result;
  }

  it("should match AVM output", async () => {
    const input = {
      msg: 7n,
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);

    const output = witness[1];
    expect(output).toBeDefined();

    const result = await client.send.mimcTest({ args: { v: 7n } });

    expect(bytesToBigInt(result.return!)).toEqual(output);
  });
});
