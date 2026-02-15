import { describe, it, beforeAll, expect } from "vitest";
import { CircuitTester, MimcCalculator } from "./utils/test-utils";
import { PlonkAppVerifier } from "snarkjs-algorand";
import { AlgorandClient } from "@algorandfoundation/algokit-utils";

describe("Deposit Circuit", () => {
  let circuit: any;
  let mimc: MimcCalculator;

  beforeAll(async () => {
    circuit = await CircuitTester.create({
      circuitPath: "circuits/deposit.circom",
    });
    mimc = await MimcCalculator.create();
  });

  async function sum4Commit(a: bigint, b: bigint, c: bigint, d: bigint) {
    return await mimc.sum4Commit([a, b, c, d]);
  }

  it("computes commitment = MiMC_Sum(spend,null,amount,receiver)", async () => {
    const spending_secret = 111n;
    const nullifier_secret = 222n;
    const amount = 333n;
    const receiver = 444n;

    const expected = await sum4Commit(
      spending_secret,
      nullifier_secret,
      amount,
      receiver,
    );

    const witness = await circuit.calculateWitness({
      amount,
      receiver,
      spending_secret,
      nullifier_secret,
    });
    await circuit.checkConstraints(witness);

    const commitment = witness[1];
    expect(commitment).toBe(expected);
  });

  it("handles zeros", async () => {
    const spending_secret = 0n;
    const nullifier_secret = 0n;
    const amount = 0n;
    const receiver = 0n;

    const expected = await sum4Commit(
      spending_secret,
      nullifier_secret,
      amount,
      receiver,
    );

    const witness = await circuit.calculateWitness({
      amount,
      receiver,
      spending_secret,
      nullifier_secret,
    });
    await circuit.checkConstraints(witness);
    expect(witness[1]).toBe(expected);
  });

  it("verifies on chain", async () => {
    const algorand = AlgorandClient.defaultLocalNet();
    const verifier = new PlonkAppVerifier({
      algorand,
      zKey: "circuits/deposit_test.zkey",

      wasmProver: "circuits/deposit_js/deposit.wasm",
    });

    await verifier.deploy({
      defaultSender: await algorand.account.localNetDispenser(),
      onUpdate: "append",
      debugLogging: false,
    });

    const spending_secret = 111n;
    const nullifier_secret = 222n;
    const amount = 333n;
    const receiver = 444n;

    const simRes = await verifier.simulateVerification(
      {
        spending_secret,
        nullifier_secret,
        amount,
        receiver,
      },
      { extraOpcodeBudget: 20_000 * 16 },
    );

    expect(
      simRes.simulateResponse.txnGroups[0]!.appBudgetConsumed,
    ).toMatchSnapshot("deposit verification budget");
  });
});
