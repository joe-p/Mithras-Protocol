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
  UtxoSecrets,
} from "../../mithras-crypto/src";

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

export class MithrasSubscriber {
  public amount: bigint = 0n;
  public utxos: Map<Uint8Array, bigint> = new Map();

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
          const amount = this.utxos.get(method.nullifier!)!;
          this.amount -= amount;
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
          this.utxos.set(nullifier, utxo.amount);
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
