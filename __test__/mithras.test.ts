import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import { AppVerifier, LsigVerifier } from "snarkjs-algorand";
import { MithrasClient, MithrasFactory } from "../contracts/clients/Mithras";

import { beforeAll, describe, expect, it } from "vitest";
import { MerkleTestHelpers } from "./utils/test-utils";

const DEPOSIT_LSIGS = 6;
const SPEND_LSIGS = 14;

describe("Mithras App", () => {
  let depositVerifier: LsigVerifier;
  let spendVerifier: LsigVerifier;
  let appClient: MithrasClient;
  let algorand: AlgorandClient;

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    algorand.setSuggestedParamsCacheTimeout(0);
    depositVerifier = new LsigVerifier(
      algorand,
      "circuits/deposit_test.zkey",
      "circuits/deposit_js/deposit.wasm",
    );

    spendVerifier = new LsigVerifier(
      algorand,
      "circuits/spend_test.zkey",
      "circuits/spend_js/spend.wasm",
    );

    const factory = new MithrasFactory({
      algorand,
      defaultSender: await algorand.account.localNetDispenser(),
    });

    const { appClient: ac } = await factory.send.create.createApplication({
      args: {
        depositVerifier: (await depositVerifier.lsigAccount()).addr.toString(),
        spendVerifier: (await spendVerifier.lsigAccount()).addr.toString(),
      },
    });

    appClient = ac;

    // TODO: determine the actual MBR needed
    await appClient.appClient.fundAppAccount({ amount: microAlgos(4848000) });

    await appClient.send.bootstrapMerkleTree({
      args: {},
      // TODO: determine the actual fee needed
      extraFee: microAlgos(256 * 1000),
    });
  });

  it("deposit", async () => {
    const spending_secret = 1n;
    const nullifier_secret = 2n;
    const amount = 3n;
    const receiver = 4n;

    const verifierGroup = await depositVerifier.proofAndSignalsComposer(
      {
        spending_secret,
        nullifier_secret,
        amount,
        receiver,
      },
      DEPOSIT_LSIGS,
      0n,
      await algorand.account.localNetDispenser(),
    );

    const { transactions } = await verifierGroup.buildTransactions();

    const group = appClient.newGroup().deposit({
      args: [transactions[transactions.length - 1]],
      extraFee: microAlgos(256 * 1000),
    });

    for (let i = 0; i < transactions.length - 1; i++) {
      group.addTransaction(transactions[i]);
    }

    const simRes = await group.simulate({
      allowUnnamedResources: true,
    });

    expect(
      simRes.simulateResponse.txnGroups[0].appBudgetConsumed,
    ).toMatchSnapshot("deposit app budget");
  });

  it("spend", async () => {
    const utxo_spending_secret = 11n;
    const utxo_nullifier_secret = 22n;
    const utxo_amount = 33n;
    const utxo_spender = 44n;

    const depositVerifierGroup = await depositVerifier.proofAndSignalsComposer(
      {
        spending_secret: utxo_spending_secret,
        nullifier_secret: utxo_nullifier_secret,
        amount: utxo_amount,
        receiver: utxo_spender,
      },
      DEPOSIT_LSIGS,
      0n,
      await algorand.account.localNetDispenser(),
    );

    const { transactions: depositTransactions } =
      await depositVerifierGroup.buildTransactions();

    const depositGroup = appClient.newGroup().deposit({
      args: [depositTransactions[depositTransactions.length - 1]],
      extraFee: microAlgos(256 * 1000),
    });

    for (let i = 0; i < depositTransactions.length - 1; i++) {
      depositGroup.addTransaction(depositTransactions[i]);
    }

    await depositGroup.send();

    const fee = 0n;
    const out0_amount = 11n;
    const out1_amount = 22n;
    const out0_receiver = 1234n;
    const out1_receiver = 5678n;
    const out0_spending_secret = 333n;
    const out0_nullifier_secret = 444n;
    const out1_spending_secret = 555n;
    const out1_nullifier_secret = 666n;

    // Build a trivial path: all zeros to compute root
    const pathElements = MerkleTestHelpers.createDefaultPathElements();
    const pathSelectors = MerkleTestHelpers.createDefaultPathSelectors();

    const inputSignals = {
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
    };

    const spendVerifierGroup = await spendVerifier.proofAndSignalsComposer(
      inputSignals,
      SPEND_LSIGS,
      0n,
      await algorand.account.localNetDispenser(),
    );

    const { transactions: spendTransactions } =
      await spendVerifierGroup.buildTransactions();

    const spendGroup = appClient.newGroup().spend({
      args: [spendTransactions[spendTransactions.length - 1]],
      extraFee: microAlgos(256 * 1000),
    });

    for (let i = 0; i < spendTransactions.length - 1; i++) {
      spendGroup.addTransaction(spendTransactions[i]);
    }

    const simRes = await spendGroup.simulate({
      allowUnnamedResources: true,
    });

    expect(
      simRes.simulateResponse.txnGroups[0].appBudgetConsumed,
    ).toMatchSnapshot("spend app budget");
  });
});
