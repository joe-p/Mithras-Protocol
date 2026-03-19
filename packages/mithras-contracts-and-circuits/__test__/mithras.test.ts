import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import {
  PlonkLsigVerifier,
  PlonkSignalsAndProofClient,
  PlonkSignalsAndProofFactory,
} from "snarkjs-algorand";
import { MithrasClient, MithrasFactory } from "../contracts/clients/Mithras";

import { beforeAll, describe, expect, it } from "vitest";
import { MerkleTestHelpers, MimcCalculator } from "./utils/test-utils";
import { Address } from "algosdk";
import {
  commitUtxo,
  composeCommitUtxoGroup,
  DEPOSIT_APP_FEE,
  depositVerifier,
  getCommitLsig,
  MithrasProtocolClient,
  SPEND_APP_FEE,
  spendVerifier,
} from "../src";
import {
  ViewKeypair,
  MithrasAddr,
  SpendKeypair,
  SupportedHpkeSuite,
  MimcMerkleTree,
} from "../../mithras-crypto/src";
import { TREE_DEPTH } from "../src/constants";
import { MimcMerkle } from "../contracts/mimc_merkle/mimc_merkle.algo";

const SPEND_LSIGS = 12;
const LSIGS_FEE = BigInt(SPEND_LSIGS) * 1000n;
const NULLIFIER_MBR = 15_700n;

const BLS12_381_SCALAR_MODULUS = BigInt(
  "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
);

function addressInScalarField(addr: Address): bigint {
  const asBigint = BigInt("0x" + Buffer.from(addr.publicKey).toString("hex"));
  return asBigint % BLS12_381_SCALAR_MODULUS;
}

describe("Mithras App", () => {
  let appClient: MithrasClient;
  let algorand: AlgorandClient;
  let mimcCalculator: MimcCalculator;
  let depositor: Address;
  let spender: Address;

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    depositor = await algorand.account.localNetDispenser();
    spender = algorand.account.random();

    algorand.setSuggestedParamsCacheTimeout(0);
    mimcCalculator = await MimcCalculator.create();

    const deployment = await MithrasProtocolClient.deploy(algorand, depositor);
    appClient = algorand.client.getTypedAppClientById(MithrasClient, {
      appId: deployment.appClient.appId,
      defaultSender: depositor,
    });
  });

  it("deposit", async () => {
    const client = new MithrasProtocolClient(algorand, appClient.appId);
    const tree = new MimcMerkleTree();
    tree.addLeaf(0n);

    const preRoot = await appClient.state.global.currentRoot();
    expect(preRoot).toBe(tree.getRoot());

    const { group, utxoCommitment } = await client.composeDepositGroup(
      depositor,
      1n,
      MithrasAddr.fromKeys(
        SpendKeypair.generate().publicKey,
        ViewKeypair.generate().publicKey,
        1,
        0,
        SupportedHpkeSuite.x25519Sha256ChaCha20Poly1305,
      ),
    );

    const simRes = await group.simulate({
      allowUnnamedResources: true,
    });

    expect(
      simRes.simulateResponse.txnGroups[0].appBudgetConsumed,
    ).toMatchSnapshot("deposit app budget");

    await group.send();

    const commitArgs = tree.addLeaf(utxoCommitment);

    // Verify the leaf was added to pendingLeaves but the root hasn't been updated yet since we haven't committed
    const pendingLeaves = await appClient.state.box.pendingLeaves.getMap();
    expect(pendingLeaves.size).toBe(1);
    expect(pendingLeaves.get(utxoCommitment)).toEqual({
      index: 1n,
      incentive: 0n,
    });
    expect(await appClient.state.global.currentRoot()).toBe(preRoot);

    // Now commit the leaf and ensure the root is updated and pendingLeaves is cleared
    const commitGroup = await composeCommitUtxoGroup(
      algorand,
      appClient.appId,
      depositor,
      commitArgs,
    );

    await commitGroup.send();

    const postRoot = await appClient.state.global.currentRoot();
    expect(postRoot).not.toBe(preRoot);
    expect(postRoot).toBe(tree.getRoot());

    expect(await appClient.state.box.pendingLeaves.getMap()).toEqual(new Map());
  });

  it("spend", async () => {
    const utxo_spending_secret = 11n;
    const utxo_nullifier_secret = 22n;
    const utxo_amount = 200_000n;
    const utxo_spender = addressInScalarField(spender);

    const depositGroup = appClient.newGroup();

    await depositVerifier(algorand).verificationParams({
      composer: depositGroup,
      inputs: {
        spending_secret: utxo_spending_secret,
        nullifier_secret: utxo_nullifier_secret,
        amount: utxo_amount,
        receiver: utxo_spender,
      },
      paramsCallback: async (params) => {
        const { lsigParams, args, lsigsFee } = params;

        // App call from lsig to expose the signals and proof to our app
        const verifierTxn = algorand.createTransaction.payment({
          ...lsigParams,
          receiver: lsigParams.sender,
          amount: microAlgos(0),
        });

        depositGroup.deposit({
          args: {
            verifierTxn,
            signals: args.signals,
            _proof: args.proof,
            _outHpke: new Uint8Array(250),
            deposit: algorand.createTransaction.payment({
              sender: depositor,
              receiver: appClient.appAddress,
              amount: microAlgos(utxo_amount),
            }),
          },
          extraFee: microAlgos(DEPOSIT_APP_FEE + lsigsFee.microAlgos + 1000n),
        });
      },
    });

    await depositGroup.send();

    const initialSpenderBalance = (
      await algorand.account.getInformation(spender)
    ).balance.microAlgo;

    expect(initialSpenderBalance).toEqual(0n);

    const feePayment = await algorand.createTransaction.payment({
      sender: spender,
      receiver: appClient.appAddress,
      amount: microAlgos(0),
      extraFee: microAlgos(SPEND_APP_FEE + LSIGS_FEE + 1000n),
      closeRemainderTo: appClient.appAddress,
    });

    const fee = NULLIFIER_MBR + feePayment.fee;
    const out0_amount = 100_000n - fee;
    const out1_amount = 100_000n;
    const out0_receiver = addressInScalarField(algorand.account.random());
    const out1_receiver = addressInScalarField(algorand.account.random());
    const out0_spending_secret = 333n;
    const out0_nullifier_secret = 444n;
    const out1_spending_secret = 555n;
    const out1_nullifier_secret = 666n;

    // Compute the zero hashes the same way the contract does in bootstrap()
    // tree[0] = bzero(32), tree[i] = mimc(tree[i-1] + tree[i-1])
    const pathElements: bigint[] = [];
    let currentZero = 0n; // bzero(32) = 0n

    for (let i = 0; i < TREE_DEPTH; i++) {
      pathElements[i] = currentZero;
      currentZero = await mimcCalculator.calculateHash(
        currentZero,
        currentZero,
      );
    }

    const pathSelectors = MerkleTestHelpers.createDefaultPathSelectors(); // All 0s for index 0 (left path)

    // Verify this path is correct by computing what the root should be
    const utxoCommitment = await mimcCalculator.sum4Commit([
      utxo_spending_secret,
      utxo_nullifier_secret,
      utxo_amount,
      utxo_spender,
    ]);
    const expectedRoot = await mimcCalculator.calculateMerkleRoot(
      utxoCommitment,
      pathElements,
      pathSelectors,
    );

    const onChainRoot = await appClient.state.global.lastComputedRoot();

    expect(expectedRoot).toBe(onChainRoot);

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

    await spendVerifier(algorand).verificationParams({
      composer: spendGroup,
      inputs: inputSignals,
      paramsCallback: async (params) => {
        const { lsigParams, args } = params;

        const verifierTxn = algorand.createTransaction.payment({
          ...lsigParams,
          receiver: lsigParams.sender,
          amount: microAlgos(0),
        });

        spendGroup.spend({
          sender: spender,
          args: {
            verifierTxn,
            signals: args.signals,
            _proof: args.proof,
            _out0Hpke: new Uint8Array(250),
            _out1Hpke: new Uint8Array(250),
          },
          staticFee: microAlgos(0),
        });
        spendGroup.addTransaction(feePayment);
      },
    });

    const simRes = await spendGroup.simulate({
      allowUnnamedResources: true,
    });

    expect(
      simRes.simulateResponse.txnGroups[0].appBudgetConsumed,
    ).toMatchSnapshot("spend app budget");

    await spendGroup.send();

    const finalSpenderBalance = (await algorand.account.getInformation(spender))
      .balance.microAlgo;

    expect(finalSpenderBalance).toEqual(0n);
  });
});
