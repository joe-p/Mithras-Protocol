import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import { AppVerifier } from "snarkjs-algorand";
import { MithrasClient, MithrasFactory } from "../contracts/clients/Mithras";

import { beforeAll, describe, expect, it } from "vitest";
import { MerkleTestHelpers } from "./utils/test-utils";

const DEPOSIT_BUDGET = 174541;
const SPEND_BUDGET = 356664;

describe("Mithras App", () => {
  let depositVerifier: AppVerifier;
  let spendVerifier: AppVerifier;
  let appClient: MithrasClient;

  beforeAll(async () => {
    const algorand = AlgorandClient.defaultLocalNet();
    depositVerifier = new AppVerifier(
      algorand,
      "circuits/deposit_test.zkey",
      "circuits/deposit_js/deposit.wasm",
    );

    await depositVerifier.deploy({
      defaultSender: await algorand.account.localNetDispenser(),
      onUpdate: "append",
    });

    spendVerifier = new AppVerifier(
      algorand,
      "circuits/spend_test.zkey",
      "circuits/spend_js/spend.wasm",
    );

    await spendVerifier.deploy({
      defaultSender: await algorand.account.localNetDispenser(),
      onUpdate: "append",
    });

    const factory = new MithrasFactory({
      algorand,
      defaultSender: await algorand.account.localNetDispenser(),
    });

    const { appClient: ac } = await factory.send.create.createApplication({
      args: {
        depositVerifierId: depositVerifier.appClient!.appId,
        spendVerifierId: spendVerifier.appClient!.appId,
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

    const verifierTxn = await depositVerifier.verifyTransaction({
      spending_secret,
      nullifier_secret,
      amount,
      receiver,
    });

    const group = appClient
      .newGroup()
      .ensureBudget({
        extraFee: microAlgos(256 * 1000),
        args: { budget: DEPOSIT_BUDGET },
      })
      .deposit({ args: [verifierTxn] });

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

    const depositVerifierTxn = await depositVerifier.verifyTransaction({
      spending_secret: utxo_spending_secret,
      nullifier_secret: utxo_nullifier_secret,
      amount: utxo_amount,
      receiver: utxo_spender,
    });

    await appClient
      .newGroup()
      .ensureBudget({
        extraFee: microAlgos(256 * 1000),
        args: { budget: DEPOSIT_BUDGET },
      })
      .deposit({ args: [depositVerifierTxn] })
      .send();

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

    const spendVerifierTxn =
      await spendVerifier.verifyTransaction(inputSignals);

    const group = appClient
      .newGroup()
      .ensureBudget({
        extraFee: microAlgos(256 * 1000),
        args: { budget: SPEND_BUDGET },
      })
      .spend({ args: [spendVerifierTxn] });

    const simRes = await group.simulate({
      extraOpcodeBudget: 20_000 * 16,
      allowUnnamedResources: true,
    });

    expect(
      simRes.simulateResponse.txnGroups[0].appBudgetConsumed,
    ).toMatchSnapshot("spend app budget");
  });
});
