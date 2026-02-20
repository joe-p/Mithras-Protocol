import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
// import { PlonkLsigVerifier } from "snarkjs-algorand";
import { Groth16Bls12381LsigVerifier } from "snarkjs-algorand";
import { MithrasClient, MithrasFactory } from "../contracts/clients/Mithras";
import path from "path";

import {
  bytesToNumberBE,
  MerkleProof,
  MithrasAddr,
  SpendKeypair,
  TransactionMetadata,
  StealthKeypair,
  UtxoInputs,
  UtxoSecrets,
} from "../../mithras-crypto/src";
import algosdk from "algosdk";
import { equalBytes } from "../../mithras-subscriber/src";

const DEPOSIT_LSIGS = 7;
const SPEND_LSIGS = 12;
const LSIGS_FEE = BigInt(SPEND_LSIGS) * 1000n;
const SPEND_APP_FEE = 57n * 1000n;
const DEPOSIT_APP_FEE = 27n * 1000n;
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

// export function depositVerifier(algorand: AlgorandClient): PlonkLsigVerifier {
export function depositVerifier(algorand: AlgorandClient): Groth16Bls12381LsigVerifier {
  const thisFileDir = new URL(".", import.meta.url);

  const zKey = path.join(thisFileDir.pathname, "../circuits/deposit_test.zkey");
  const wasmProver = path.join(
    thisFileDir.pathname,
    "../circuits/deposit_js/deposit.wasm",
  );
  // return new PlonkLsigVerifier({
  return new Groth16Bls12381LsigVerifier({
    algorand,
    zKey,
    wasmProver,
    totalLsigs: DEPOSIT_LSIGS,
    appOffset: 1,
  });
}

// export function spendVerifier(algorand: AlgorandClient): PlonkLsigVerifier {
export function spendVerifier(algorand: AlgorandClient): Groth16Bls12381LsigVerifier {
  const thisFileDir = new URL(".", import.meta.url);
  const zKey = path.join(thisFileDir.pathname, "../circuits/spend_test.zkey");
  const wasmProver = path.join(
    thisFileDir.pathname,
    "../circuits/spend_js/spend.wasm",
  );

  // return new PlonkLsigVerifier({
  return new Groth16Bls12381LsigVerifier({
    algorand,
    zKey,
    wasmProver,
    totalLsigs: SPEND_LSIGS,
    appOffset: 1,
  });
}

type Output = {
  receiver: MithrasAddr;
  amount: bigint;
};

export class MithrasProtocolClient {
  // depositVerifier: PlonkLsigVerifier;
  // spendVerifier: PlonkLsigVerifier;
  depositVerifier: Groth16Bls12381LsigVerifier;
  spendVerifier: Groth16Bls12381LsigVerifier;
  appClient: MithrasClient;
  private _zeroHashes?: bigint[];

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
    deployer: algosdk.Address,
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

  async getZeroHashes(): Promise<bigint[]> {
    return this._zeroHashes ?? (await this.appClient.state.box.zeroHashes())!;
  }

  async composeDepositGroup(
    depositor: algosdk.Address,
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
        spending_secret: inputs.secrets.spendingSecret,
        nullifier_secret: inputs.secrets.nullifierSecret,
        amount,
        receiver: addressInScalarField(inputs.secrets.stealthPubkey),
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

  async composeSpendGroup(
    spender: MithrasAddr,
    spendKeypair: SpendKeypair,
    utxoSecrets: UtxoSecrets,
    merkleProof: MerkleProof,
    out0: Output,
    out1?: Output,
  ) {
    const contractRoot = await this.appClient.state.global.lastComputedRoot();

    if (contractRoot !== merkleProof.root) {
      throw new Error(
        `Merkle proof root does not match contract's last computed root. Got ${merkleProof.root}, expected ${contractRoot}`,
      );
    }

    const spendGroup = this.appClient.newGroup();

    const addr = new algosdk.Address(utxoSecrets.stealthPubkey);
    const stealthSigner = StealthKeypair.derive(
      spendKeypair,
      utxoSecrets.stealthScalar,
    );

    if (!equalBytes(stealthSigner.publicKey, utxoSecrets.stealthPubkey)) {
      throw new Error(
        `Stealth keypair does not derive the expected public key. Got ${stealthSigner.publicKey}, expected ${utxoSecrets.stealthPubkey}`,
      );
    }

    const signer: algosdk.TransactionSigner = async (
      txns: algosdk.Transaction[],
      indexesToSign: number[],
    ) => {
      const signedTxns: Uint8Array[] = [];

      for (const index of indexesToSign) {
        const txn = txns[index];
        const sig = stealthSigner.rawSign(txn.bytesToSign());
        const stxn = new algosdk.SignedTransaction({ txn, sig });
        signedTxns.push(algosdk.encodeMsgpack(stxn));
      }

      return signedTxns;
    };

    const senderSigner = { sender: addr, signer };

    this.algorand.account.setSigner(addr, signer);

    const feePayment = await this.algorand.createTransaction.payment({
      ...senderSigner,
      receiver: addr,
      amount: microAlgos(0),
      extraFee: microAlgos(SPEND_APP_FEE + LSIGS_FEE + 1000n),
      closeRemainderTo: this.appClient.appAddress,
    });

    const fee = NULLIFIER_MBR + feePayment.fee;

    const sp = await this.algorand.getSuggestedParams();
    const txnMetadata = new TransactionMetadata(
      stealthSigner.publicKey,
      BigInt(sp.firstValid),
      BigInt(sp.lastValid),
      new Uint8Array(32),
      0,
      this.appClient.appId,
    );

    const inputs0 = await UtxoInputs.generate(
      txnMetadata,
      out0.amount,
      out0.receiver,
    );

    if (out0.amount + fee > utxoSecrets.amount) {
      throw new Error(
        `out0 amount plus fee cannot exceed input amount. Got ${out0.amount} + ${fee} > ${utxoSecrets.amount}`,
      );
    }

    const out1Amount = out1?.amount ?? utxoSecrets.amount - out0.amount - fee;

    if (
      out1 !== undefined &&
      out0.amount + out1.amount !== utxoSecrets.amount - fee
    ) {
      throw new Error(
        `Output amounts must sum to input amount minus fee. Got ${out0.amount} + ${out1.amount} != ${utxoSecrets.amount} - ${fee}`,
      );
    }

    if (out0.amount + out1Amount > utxoSecrets.amount - fee) {
      throw new Error(
        `Output amounts cannot exceed input amount minus fee. Got ${out0.amount} + ${out1Amount} > ${utxoSecrets.amount} - ${fee}`,
      );
    }

    const inputs1 = await UtxoInputs.generate(
      txnMetadata,
      out1?.amount ?? out1Amount,
      out1?.receiver ?? spender,
    );

    const inputSignals: Record<string, bigint | bigint[]> = {
      fee,
      utxo_spender: addressInScalarField(utxoSecrets.stealthPubkey),
      utxo_spending_secret: utxoSecrets.spendingSecret,
      utxo_nullifier_secret: utxoSecrets.nullifierSecret,
      utxo_amount: utxoSecrets.amount,
      path_selectors: merkleProof.pathSelectors.map((b) => BigInt(b)),
      utxo_path: merkleProof.pathElements,
      out0_amount: out0.amount,
      out0_receiver: addressInScalarField(inputs0.secrets.stealthPubkey),
      out0_spending_secret: inputs0.secrets.spendingSecret,
      out0_nullifier_secret: inputs0.secrets.nullifierSecret,
      out1_amount: out1Amount,
      out1_receiver: addressInScalarField(inputs1.secrets.stealthPubkey),
      out1_spending_secret: inputs1.secrets.spendingSecret,
      out1_nullifier_secret: inputs1.secrets.nullifierSecret,
    };

    await this.spendVerifier.verificationParams({
      composer: spendGroup,
      inputs: inputSignals,
      paramsCallback: async (params) => {
        const { lsigParams, args } = params;

        const verifierTxn = this.algorand.createTransaction.payment({
          ...lsigParams,
          receiver: lsigParams.sender,
          amount: microAlgos(0),
        });

        spendGroup.spend({
          ...senderSigner,
          args: {
            verifierTxn,
            signals: args.signals,
            _proof: args.proof,
            _out0Hpke: inputs0.hpkeEnvelope.toBytes(),
            _out1Hpke: inputs1.hpkeEnvelope.toBytes(),
          },
          staticFee: microAlgos(0),
          firstValidRound: txnMetadata.firstValid,
          lastValidRound: txnMetadata.lastValid,
          lease: txnMetadata.lease,
        });

        spendGroup.addTransaction(feePayment);
      },
    });

    return spendGroup;
  }
}
