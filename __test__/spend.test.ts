import { describe, it, beforeAll, expect } from "vitest";
import {
  CircuitTester,
  MimcCalculator,
  MerkleTestHelpers,
} from "./utils/test-utils";

describe("Spend Circuit", () => {
  let circuit: any;
  let mimc: MimcCalculator;

  beforeAll(async () => {
    circuit = await CircuitTester.create({
      circuitPath: "circuits/spend.circom",
    });
    mimc = await MimcCalculator.create();
  });

  it("verifies merkle path, outputs, balance, nullifier", async () => {
    const fee = 7n;
    const utxo_spender = 999n;
    const utxo_spending_secret = 111n;
    const utxo_nullifier_secret = 222n;
    const utxo_amount = 1000n;

    const out0_amount = 500n;
    const out1_amount = 493n; // 500 + 493 + 7 = 1000
    const out0_receiver = 1234n;
    const out1_receiver = 5678n;
    const out0_spending_secret = 333n;
    const out0_nullifier_secret = 444n;
    const out1_spending_secret = 555n;
    const out1_nullifier_secret = 666n;

    const utxo_commitment = await mimc.sum4Commit([
      utxo_spending_secret,
      utxo_nullifier_secret,
      utxo_amount,
      utxo_spender,
    ]);

    // Build a trivial path: all zeros to compute root
    const pathElements = MerkleTestHelpers.createDefaultPathElements();
    const pathSelectors = MerkleTestHelpers.createDefaultPathSelectors();
    const utxo_root = await mimc.calculateMerkleRoot(
      utxo_commitment,
      pathElements,
      pathSelectors,
    );

    const out0_commitment = await mimc.sum4Commit([
      out0_spending_secret,
      out0_nullifier_secret,
      out0_amount,
      out0_receiver,
    ]);
    const out1_commitment = await mimc.sum4Commit([
      out1_spending_secret,
      out1_nullifier_secret,
      out1_amount,
      out1_receiver,
    ]);

    const witness = await circuit.calculateWitness({
      fee,
      utxo_spender,
      utxo_spending_secret,
      utxo_nullifier_secret,
      utxo_amount,
      path_selectors: pathSelectors,
      utxo_path: pathElements,
      out0_amount,
      out0_receiver,
      out0_spending_secret,
      out0_nullifier_secret,
      out1_amount,
      out1_receiver,
      out1_spending_secret,
      out1_nullifier_secret,
    });
    await circuit.checkConstraints(witness);

    // Outputs
    expect(witness[1]).toBe(out0_commitment);
    expect(witness[2]).toBe(out1_commitment);
    // Root
    expect(witness[3]).toBe(utxo_root);
    // Nullifier is MiMC_Sum(4) over the same tuple as utxo_commitment
    const expected_nullifier = await mimc.calculateHash(
      utxo_commitment,
      utxo_nullifier_secret,
    );
    expect(witness[4]).toBe(expected_nullifier);
  });

  it("fails when balance doesn't add up", async () => {
    const fee = 1n;
    const utxo_spender = 1n;
    const utxo_spending_secret = 2n;
    const utxo_nullifier_secret = 3n;
    const utxo_amount = 10n;

    const out0_amount = 5n;
    const out1_amount = 5n; // 5 + 5 + 1 != 10

    const utxo_commitment = await mimc.sum4Commit([
      utxo_spending_secret,
      utxo_nullifier_secret,
      utxo_amount,
      utxo_spender,
    ]);

    const pathElements = MerkleTestHelpers.createDefaultPathElements();
    const pathSelectors = MerkleTestHelpers.createDefaultPathSelectors();

    await expect(async () => {
      const witness = await circuit.calculateWitness({
        fee,
        utxo_spender,
        utxo_spending_secret,
        utxo_nullifier_secret,
        utxo_amount,
        path_selectors: pathSelectors,
        utxo_path: pathElements,
        out0_amount,
        out0_receiver: 0n,
        out0_spending_secret: 0n,
        out0_nullifier_secret: 0n,
        out1_amount,
        out1_receiver: 0n,
        out1_spending_secret: 0n,
        out1_nullifier_secret: 0n,
      });
      await circuit.checkConstraints(witness);
    }).rejects.toThrow();
  });
});
