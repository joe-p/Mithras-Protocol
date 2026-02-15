import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import { PlonkLsigVerifier } from "snarkjs-algorand";
import { MithrasClient, MithrasFactory } from "../contracts/clients/Mithras";
import path from "path";
import { Address } from "algosdk";
import {
  bytesToNumberBE,
  MithrasAddr,
  TransactionMetadata,
  UtxoInputs,
} from "../../mithras-crypto/src";

const SPEND_LSIGS = 12;
const LSIGS_FEE = BigInt(SPEND_LSIGS) * 1000n;
const SPEND_APP_FEE = 110n * 1000n;
const DEPOSIT_APP_FEE = 53n * 1000n;
const APP_MBR = 1567900n;
const BOOTSTRAP_FEE = 51n * 1000n;
const NULLIFIER_MBR = 15_700n;
const BLS12_381_SCALAR_MODULUS = BigInt(
  "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
);

export function addressInScalarField(addr: Uint8Array): bigint {
  const asBigint = BigInt("0x" + Buffer.from(addr).toString("hex"));
  return asBigint % BLS12_381_SCALAR_MODULUS;
}

export function depositVerifier(algorand: AlgorandClient): PlonkLsigVerifier {
  const thisFileDir = new URL(".", import.meta.url);

  const zKey = path.join(thisFileDir.pathname, "../circuits/deposit_test.zkey");
  const wasmProver = path.join(
    thisFileDir.pathname,
    "../circuits/deposit_js/deposit.wasm",
  );
  return new PlonkLsigVerifier({
    algorand,
    zKey,
    wasmProver,
    totalLsigs: 7,
    appOffset: 1,
  });
}

export function spendVerifier(algorand: AlgorandClient): PlonkLsigVerifier {
  const thisFileDir = new URL(".", import.meta.url);
  const zKey = path.join(thisFileDir.pathname, "../circuits/spend_test.zkey");
  const wasmProver = path.join(
    thisFileDir.pathname,
    "../circuits/spend_js/spend.wasm",
  );

  return new PlonkLsigVerifier({
    algorand,
    zKey,
    wasmProver,
    totalLsigs: 12,
    appOffset: 1,
  });
}

export class MithrasProtocolClient {
  depositVerifier: PlonkLsigVerifier;
  spendVerifier: PlonkLsigVerifier;
  appClient: MithrasClient;

  constructor(
    public algorand: AlgorandClient,
    appId: bigint,
  ) {
    this.depositVerifier = depositVerifier(algorand);
    this.spendVerifier = spendVerifier(algorand);

    this.appClient = algorand.client.getTypedAppClientById(MithrasClient, {
      appId,
    });
  }

  static async deploy(
    algorand: AlgorandClient,
    deployer: Address,
  ): Promise<MithrasProtocolClient> {
    const factory = new MithrasFactory({
      algorand,
      defaultSender: deployer,
    });

    const { appClient } = await factory.send.create.createApplication({
      args: {
        depositVerifier: (
          await depositVerifier(algorand).lsigAccount()
        ).addr.toString(),
        spendVerifier: (
          await spendVerifier(algorand).lsigAccount()
        ).addr.toString(),
      },
    });

    await appClient.appClient.fundAppAccount({ amount: microAlgos(APP_MBR) });

    await appClient.send.bootstrapMerkleTree({
      args: {},
      extraFee: microAlgos(BOOTSTRAP_FEE),
    });

    return new MithrasProtocolClient(algorand, appClient.appId);
  }

  async composeDepositGroup(
    depositor: Address,
    amount: bigint,
    receiver: MithrasAddr,
  ) {
    const group = this.appClient.newGroup();

    const sp = await this.algorand.getSuggestedParams();
    const txnMetadata = new TransactionMetadata(
      depositor.publicKey,
      BigInt(sp.firstValid),
      BigInt(sp.lastValid),
      new Uint8Array(32),
      0,
      this.appClient.appId,
    );
    const inputs = await UtxoInputs.generate(txnMetadata, amount, receiver);

    await this.depositVerifier.verificationParams({
      composer: group,
      inputs: {
        spending_secret: bytesToNumberBE(inputs.secrets.spendingSecret),
        nullifier_secret: bytesToNumberBE(inputs.secrets.nullifierSecret),
        amount,
        receiver: addressInScalarField(inputs.secrets.tweakedPubkey),
      },
      paramsCallback: async (params) => {
        const { lsigParams, lsigsFee, args } = params;

        const verifierTxn = this.algorand.createTransaction.payment({
          ...lsigParams,
          receiver: lsigParams.sender,
          amount: microAlgos(0),
        });

        group.deposit({
          sender: depositor,
          firstValidRound: txnMetadata.firstValid,
          lastValidRound: txnMetadata.lastValid,
          lease: txnMetadata.lease,
          args: {
            _outHpke: inputs.hpkeEnvelope.toBytes(),
            verifierTxn,
            signals: args.signals,
            _proof: args.proof,
            deposit: this.algorand.createTransaction.payment({
              sender: depositor,
              receiver: this.appClient.appAddress,
              amount: microAlgos(amount),
            }),
          },
          extraFee: microAlgos(DEPOSIT_APP_FEE + lsigsFee.microAlgos + 1000n),
        });
      },
    });

    return { group, txnMetadata };
  }
}
