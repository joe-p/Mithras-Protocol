import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import {
  LsigVerifier,
  SignalsAndProofClient,
  SignalsAndProofFactory,
} from "snarkjs-algorand";
import { MithrasClient, MithrasFactory } from "../contracts/clients/Mithras";

import { beforeAll, describe, expect, it } from "vitest";
import { MerkleTestHelpers, MimcCalculator } from "./utils/test-utils";
import { Address } from "algosdk";

const SPEND_APP_FEE = 108n * 1000n;
const DEPOSIT_APP_FEE = 53n * 1000n;
const APP_MBR = 1567900n;
const BOOTSTRAP_FEE = 51n * 1000n;

const BLS12_381_SCALAR_MODULUS = BigInt(
  "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
);

function addressInScalarField(addr: Address): bigint {
  const asBigint = BigInt("0x" + Buffer.from(addr.publicKey).toString("hex"));
  return asBigint % BLS12_381_SCALAR_MODULUS;
}

describe("Mithras App", () => {
  let depositVerifier: LsigVerifier;
  let spendVerifier: LsigVerifier;
  let appClient: MithrasClient;
  let algorand: AlgorandClient;
  let signalsAndProofClient: SignalsAndProofClient;
  let mimcCalculator: MimcCalculator;
  let spender: Address;

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    spender = await algorand.account.localNetDispenser();
    algorand.setSuggestedParamsCacheTimeout(0);
    mimcCalculator = await MimcCalculator.create();
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

    await appClient.appClient.fundAppAccount({ amount: microAlgos(APP_MBR) });

    await appClient.send.bootstrapMerkleTree({
      args: {},
      extraFee: microAlgos(BOOTSTRAP_FEE),
    });
  });

  it("deposit", async () => {
    const spending_secret = 1n;
    const nullifier_secret = 2n;
    const amount = 3n;
    const receiver = addressInScalarField(spender);

    const group = appClient.newGroup();

    await depositVerifier.verificationParams({
      composer: group,
      inputs: {
        spending_secret,
        nullifier_secret,
        amount,
        receiver,
      },
      paramsCallback: async (params) => {
        const { appParams, lsigsFee } = params;

        // App call from lsig to expose the signals and proof to our app
        const signalsAndProofCall = (
          await signalsAndProofClient.createTransaction.signalsAndProof(
            appParams,
          )
        ).transactions[0];

        group.deposit({
          args: {
            signalsAndProofCall,
            deposit: algorand.createTransaction.payment({
              sender: await algorand.account.localNetDispenser(),
              receiver: appClient.appAddress,
              amount: microAlgos(amount),
            }),
          },
          extraFee: microAlgos(DEPOSIT_APP_FEE + lsigsFee.microAlgos),
        });
      },
    });

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
    const utxo_amount = 200_000n;
    const utxo_spender = addressInScalarField(spender);

    const depositGroup = appClient.newGroup();

    await depositVerifier.verificationParams({
      composer: depositGroup,
      inputs: {
        spending_secret: utxo_spending_secret,
        nullifier_secret: utxo_nullifier_secret,
        amount: utxo_amount,
        receiver: utxo_spender,
      },
      paramsCallback: async (params) => {
        const { appParams, lsigsFee } = params;

        console.debug(appParams.args.signals);

        // App call from lsig to expose the signals and proof to our app
        const signalsAndProofCall = (
          await signalsAndProofClient.createTransaction.signalsAndProof(
            appParams,
          )
        ).transactions[0];

        depositGroup.deposit({
          args: {
            signalsAndProofCall,
            deposit: algorand.createTransaction.payment({
              sender: await algorand.account.localNetDispenser(),
              receiver: appClient.appAddress,
              amount: microAlgos(utxo_amount),
            }),
          },
          extraFee: microAlgos(DEPOSIT_APP_FEE + lsigsFee.microAlgos),
        });
      },
    });

    await depositGroup.send();

    const fee = 0n;
    const out0_amount = 100_000n;
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

    for (let i = 0; i < 32; i++) {
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
    const onChainRootBigInt = BigInt(
      "0x" + Buffer.from(onChainRoot.asByteArray()!).toString("hex"),
    );

    expect(expectedRoot).toBe(onChainRootBigInt);

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

    await spendVerifier.verificationParams({
      composer: spendGroup,
      inputs: inputSignals,
      paramsCallback: async (params) => {
        const { appParams, lsigsFee } = params;
        console.debug(appParams.args.signals);

        // App call from lsig to expose the signals and proof to our app
        const signalsAndProofCall = (
          await signalsAndProofClient.createTransaction.signalsAndProof(
            appParams,
          )
        ).transactions[0];

        spendGroup.spend({
          args: { verifierCall: signalsAndProofCall },
          extraFee: microAlgos(SPEND_APP_FEE + lsigsFee.microAlgos),
        });
      },
    });

    const simRes = await spendGroup.simulate({
      allowUnnamedResources: true,
    });

    expect(
      simRes.simulateResponse.txnGroups[0].appBudgetConsumed,
    ).toMatchSnapshot("spend app budget");
  });
});
