import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import {
  LsigVerifier,
  SignalsAndProofClient,
  SignalsAndProofFactory,
} from "snarkjs-algorand";
import { MithrasClient, MithrasFactory } from "../contracts/clients/Mithras";

import { beforeAll, describe, expect, it } from "vitest";
import { MerkleTestHelpers } from "./utils/test-utils";

const DEPOSIT_LSIGS = 6;
const SPEND_LSIGS = 6;

describe("Mithras App", () => {
  let depositVerifier: LsigVerifier;
  let spendVerifier: LsigVerifier;
  let appClient: MithrasClient;
  let algorand: AlgorandClient;
  let signalsAndProofClient: SignalsAndProofClient;

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    algorand.setSuggestedParamsCacheTimeout(0);
    depositVerifier = new LsigVerifier(
      algorand,
      "circuits/deposit_test.zkey",
      "circuits/deposit_js/deposit.wasm",
      DEPOSIT_LSIGS,
    );

    spendVerifier = new LsigVerifier(
      algorand,
      "circuits/spend_test.zkey",
      "circuits/spend_js/spend.wasm",
      SPEND_LSIGS,
    );

    const signalsAndProofFactory = new SignalsAndProofFactory({
      defaultSender: await algorand.account.localNetDispenser(),
      algorand,
    });

    const { appClient: sapc } = await signalsAndProofFactory.deploy({
      onUpdate: "append",
    });

    signalsAndProofClient = sapc;

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

    const group = appClient.newGroup();

    const params = await depositVerifier.verificationParams({
      spending_secret,
      nullifier_secret,
      amount,
      receiver,
    });

    const { appParams, extraLsigsTxns } = params;

    // App call from lsig to expose the signals and proof to our app
    const signalsAndProofCall = (
      await signalsAndProofClient.createTransaction.signalsAndProof(appParams)
    ).transactions[0];

    group.deposit({
      args: { signalsAndProofCall },
      extraFee: microAlgos(256 * 1000),
    });

    for (const txn of extraLsigsTxns) {
      group.addTransaction(txn);
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

    const depositGroup = appClient.newGroup();

    const depositParams = await depositVerifier.verificationParams({
      spending_secret: utxo_spending_secret,
      nullifier_secret: utxo_nullifier_secret,
      amount: utxo_amount,
      receiver: utxo_spender,
    });

    const {
      appParams: depositAppParams,
      extraLsigsTxns: depositExtraLsigTxns,
    } = depositParams;

    // App call from lsig to expose the signals and proof to our app
    const depositSignalsAndProofCall = (
      await signalsAndProofClient.createTransaction.signalsAndProof(
        depositAppParams,
      )
    ).transactions[0];

    depositGroup.deposit({
      args: { signalsAndProofCall: depositSignalsAndProofCall },
      extraFee: microAlgos(256 * 1000),
    });

    for (const txn of depositExtraLsigTxns) {
      depositGroup.addTransaction(txn);
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

    const spendGroup = appClient.newGroup();

    const params = await spendVerifier.verificationParams(inputSignals);

    const { appParams, extraLsigsTxns } = params;

    // App call from lsig to expose the signals and proof to our app
    const signalsAndProofCall = (
      await signalsAndProofClient.createTransaction.signalsAndProof(appParams)
    ).transactions[0];

    spendGroup.spend({
      args: { verifierCall: signalsAndProofCall },
      extraFee: microAlgos(256 * 1000),
    });

    for (const txn of extraLsigsTxns) {
      spendGroup.addTransaction(txn);
    }

    const simRes = await spendGroup.simulate({
      allowUnnamedResources: true,
    });

    expect(
      simRes.simulateResponse.txnGroups[0].appBudgetConsumed,
    ).toMatchSnapshot("spend app budget");
  });
});
