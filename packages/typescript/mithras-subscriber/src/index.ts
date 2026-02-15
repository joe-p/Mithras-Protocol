import { AlgorandSubscriber } from "@algorandfoundation/algokit-subscriber";
import {
  AlgorandSubscriberConfig,
  TransactionFilter,
} from "@algorandfoundation/algokit-subscriber/types/subscription";
import algosdk from "algosdk";
import {
  DiscoveryKeypair,
  HpkeEnvelope,
  SpendSeed,
  TransactionMetadata,
  TweakedSigner,
  UtxoInputs,
  UtxoSecrets,
} from "../../mithras-crypto/src";
import base32 from "hi-base32";

const DEPOSIT_SIGNATURE =
  "deposit(uint256[],(byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],uint256,uint256,uint256,uint256,uint256,uint256),byte[250],pay,txn)void";
const SPEND_SIGNATURE =
  "spend(uint256[],(byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],uint256,uint256,uint256,uint256,uint256,uint256),byte[250],byte[250],txn)void";

const DEPOSIT_SELECTOR =
  algosdk.ABIMethod.fromSignature(DEPOSIT_SIGNATURE).getSelector();
const SPEND_SELECTOR =
  algosdk.ABIMethod.fromSignature(SPEND_SIGNATURE).getSelector();

export class MithrasMethod {
  constructor(
    public type: "deposit" | "spend",
    public hpke_envelopes: HpkeEnvelope[],
    public commitments: Uint8Array[],
    public nullifier?: Uint8Array,
  ) {}

  static fromArgs(args: Uint8Array[]): MithrasMethod | null {
    if (args.length === 0) {
      return null;
    }

    const selector = args[0];

    if (selector === DEPOSIT_SELECTOR) {
      if (args.length !== 4) {
        return null;
      }

      const commitment = args[1].slice(0, 32);

      const hpkeBytes = args[3];
      const hpkeEnvelope = HpkeEnvelope.fromBytes(hpkeBytes);

      return new MithrasMethod("deposit", [hpkeEnvelope], [commitment]);
    } else if (selector === SPEND_SELECTOR) {
      if (args.length !== 5) {
        return null;
      }

      const commitment0 = args[1].slice(0, 32);
      const commitment1 = args[1].slice(32, 64);
      const nullifier = args[1].slice(96, 128);

      const hpkeBytes0 = args[3];
      const hpkeEnvelope0 = HpkeEnvelope.fromBytes(hpkeBytes0);

      const hpkeBytes1 = args[4];
      const hpkeEnvelope1 = HpkeEnvelope.fromBytes(hpkeBytes1);

      return new MithrasMethod(
        "spend",
        [hpkeEnvelope0, hpkeEnvelope1],
        [commitment0, commitment1],
        nullifier,
      );
    } else {
      return null;
    }
  }

  verifyCommitment(utxo: UtxoSecrets): boolean {
    const commitment = utxo.computeCommitment();
    return this.commitments.some((c) => c.toString() === commitment.toString());
  }
}

export type UtxoInfo = {
  amount: Uint8Array;
  round: Uint8Array;
  txid: Uint8Array;
};

export async function algodUtxoLookup(
  algod: algosdk.Algodv2,
  info: UtxoInfo,
): Promise<void> {
  const block = await algod.block(algosdk.decodeUint64(info.round)).do();
  const transaction = block.block.payset.find((t) => {
    const txn = t.signedTxn.signedTxn.txn;

    // @ts-expect-error - readonly
    txn.genesisHash = block.block.header.genesisHash;
    // @ts-expect-error - readonly
    txn.genesisID = block.block.header.genesisID;

    return txn.txID() === base32.encode(info.txid);
  });

  const newLeafCall =
    transaction?.signedTxn.applyData.evalDelta?.innerTxns.at(-1)?.signedTxn.txn
      .applicationCall;
}

export class MithrasSubscriber {
  public amount: bigint = 0n;
  /**
   * Maps nullifiers to the amount (BE uint64), round (BE uint64), and txid (raw 32 bytes) for the corresponding UTXO.
   *
   * To spend the UTXO, there needs to be a lookup of the transaction to get the merkle path from the
   * NewLeaf "log" (inner txn args). The round is included to enable lookup of the transaction with
   * an archival algod (and not a full indexer) by getting the block and then finding the tranasction
   *
   * The numbers are encoded as big-endian bytes so they have a fixed size in memory.
   * Each map value is 8 (amount) + 8 (round) + 32 (txid) = 48 bytes
   * so the memory usage of this map can be easily calculated based on the number of UTXOs stored.
   */
  public utxos: Map<Uint8Array, UtxoInfo> = new Map();

  constructor(
    algod: algosdk.Algodv2,
    appId: bigint,
    startRound: bigint,
    discoveryKeypair: DiscoveryKeypair,
    spendSeed: SpendSeed,
  ) {
    let watermark = startRound;

    const filter: TransactionFilter = {
      appId,
      methodSignature: [DEPOSIT_SIGNATURE, SPEND_SIGNATURE],
    };
    const config: AlgorandSubscriberConfig = {
      filters: [{ name: "mithras", filter }],
      syncBehaviour: "sync-oldest",
      watermarkPersistence: {
        get: async () => {
          return watermark;
        },
        set: async (newWatermark: bigint) => {
          watermark = newWatermark;
        },
      },
    };
    const subscriber = new AlgorandSubscriber(config, algod);

    subscriber.on("mithras", async (txn) => {
      const appl = txn.applicationTransaction!;

      const method = MithrasMethod.fromArgs(appl.applicationArgs!);

      if (method === null) {
        return;
      }

      if (method.type === "spend") {
        if (this.utxos.has(method.nullifier!)) {
          const { amount } = this.utxos.get(method.nullifier!)!;
          this.amount -= algosdk.decodeUint64(amount, "bigint");
          this.utxos.delete(method.nullifier!);
          return;
        }
      }

      for (const envelope of method.hpke_envelopes) {
        const txnMetadata = new TransactionMetadata(
          algosdk.Address.fromString(txn.sender).publicKey,
          txn.firstValid,
          txn.lastValid,
          txn.lease || new Uint8Array(32),
          0, // TODO: handle network ID
          appId,
        );

        if (
          !envelope.discoveryCheck(discoveryKeypair.privateKey, txnMetadata)
        ) {
          continue;
        }

        const utxo = await UtxoSecrets.fromHpkeEnvelope(
          envelope,
          discoveryKeypair,
          txnMetadata,
        );

        if (!method.verifyCommitment(utxo)) {
          continue;
        }
        const nullifier = utxo.computeNullifier();
        if (this.utxos.has(nullifier)) {
          continue;
        } else {
          this.utxos.set(nullifier, {
            round: algosdk.encodeUint64(txn.confirmedRound ?? 0n),
            amount: algosdk.encodeUint64(utxo.amount),
            txid: new Uint8Array(base32.decode.asBytes(txn.id)),
          });
        }

        const derivedSigner = TweakedSigner.derive(spendSeed, utxo.tweakScalar);

        if (
          derivedSigner.publicKey.toString() != utxo.tweakedPubkey.toString()
        ) {
          continue;
        }

        this.amount += utxo.amount;
      }
    });
  }
}
