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

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }

  return true;
}

export class MithrasMethod {
  constructor(
    public type: "deposit" | "spend",
    public hpke_envelopes: HpkeEnvelope[],
    public commitments: Uint8Array[],
    public nullifier?: Uint8Array,
  ) {}

  static fromArgs(args: readonly Uint8Array[]): MithrasMethod | null {
    if (args.length === 0) {
      console.debug("No arguments provided in application call");
      return null;
    }

    const selector = args[0];

    if (equalBytes(selector, DEPOSIT_SELECTOR)) {
      console.debug("Parsing deposit method from application call arguments");
      if (args.length !== 4) {
        return null;
      }

      const commitment = args[1].slice(0 + 2, 32 + 2);

      const hpkeBytes = args[3];
      const hpkeEnvelope = HpkeEnvelope.fromBytes(hpkeBytes);

      return new MithrasMethod("deposit", [hpkeEnvelope], [commitment]);
    } else if (equalBytes(selector, SPEND_SELECTOR)) {
      console.debug("Parsing spend method from application call arguments");
      if (args.length !== 5) {
        return null;
      }

      const commitment0 = args[1].slice(0 + 2, 32 + 2);
      const commitment1 = args[1].slice(32 + 2, 64 + 2);
      const nullifier = args[1].slice(96 + 2, 128 + 2);

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
      console.debug(
        `Unknown method selector: ${selector}. Expected ${DEPOSIT_SELECTOR} or ${SPEND_SELECTOR}`,
      );
      return null;
    }
  }

  verifyCommitment(utxo: UtxoSecrets): boolean {
    const commitment = utxo.computeCommitment();
    return this.commitments.some((c) => equalBytes(c, commitment));
  }
}

export type UtxoInfo = {
  amount: Uint8Array;
  round: Uint8Array;
  txid: Uint8Array;
};

// type NewLeaf = {
//   leaf: bytes<32>;
//   subtree: FixedArray<bytes<32>, typeof TREE_DEPTH>;
//   epochId: uint64;
//   treeIndex: uint64;
// };

type LeafInfo = {
  leaf: Uint8Array;
  subtree: Uint8Array[];
  epochId: bigint;
  treeIndex: bigint;
};

export async function algodUtxoLookup(
  algod: algosdk.Algodv2,
  info: UtxoInfo,
  discvoveryKeypair: DiscoveryKeypair,
): Promise<{ leafInfo: LeafInfo; secrets: UtxoSecrets }> {
  const block = await algod.block(algosdk.decodeUint64(info.round)).do();
  const transaction = block.block.payset.find((t) => {
    const txn = t.signedTxn.signedTxn.txn;

    // @ts-expect-error - readonly
    txn.genesisHash = block.block.header.genesisHash;

    // @ts-expect-error - readonly
    txn.genesisID = block.block.header.genesisID;

    return equalBytes(info.txid, txn.rawTxID());
  });

  console.debug("Found transaction for UTXO lookup:", transaction);

  const appl = transaction?.signedTxn.signedTxn.txn.applicationCall;

  const method = MithrasMethod.fromArgs(appl?.appArgs ?? []);

  if (method === null) {
    throw new Error("Failed to parse method from transaction application call");
  }

  const newLeafCall =
    transaction?.signedTxn.applyData.evalDelta?.innerTxns.at(-1)?.signedTxn.txn
      .applicationCall;

  if (method.type === "deposit") {
    const logType = algosdk.ABIType.from(
      "(byte[32],byte[32][24],uint64,uint64)",
    );
    const log = newLeafCall?.appArgs[1];

    if (log === undefined) {
      throw new Error("No log found in inner transaction for deposit method");
    }

    const hpkeEnv = method.hpke_envelopes[0];

    const txn = transaction?.signedTxn.signedTxn.txn!;

    const txnMetadata = new TransactionMetadata(
      txn.sender.publicKey!,
      txn.firstValid,
      txn.lastValid,
      txn.lease ?? new Uint8Array(32),
      0, // TODO: handle network ID
      appl?.appIndex!,
    );
    const secrets = await UtxoSecrets.fromHpkeEnvelope(
      hpkeEnv,
      discvoveryKeypair,
      txnMetadata,
    );

    const decodedLog = logType.decode(log);
    const leafInfo = {
      leaf: new Uint8Array(decodedLog[0]),
      subtree: decodedLog[1].map((b: number[]) => new Uint8Array(b)),
      epochId: decodedLog[2],
      treeIndex: decodedLog[3],
    };

    return { leafInfo, secrets };
  }

  throw new Error("UTXO lookup is only supported for deposit transactions");
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

  public subscriber: AlgorandSubscriber;

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
    this.subscriber = new AlgorandSubscriber(config, algod);

    this.subscriber.on("mithras", async (txn) => {
      console.debug(
        `Processing transaction ${txn.id} in round ${txn.confirmedRound}`,
      );
      const appl = txn.applicationTransaction!;

      const method = MithrasMethod.fromArgs(appl.applicationArgs!);

      if (method === null) {
        console.debug(`Failed to parse method from transaction ${txn.id}`);
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

        console.debug(
          `Performing discovery check for HPKE envelope in transaction ${txn.id}...`,
        );
        if (
          !envelope.discoveryCheck(discoveryKeypair.privateKey, txnMetadata)
        ) {
          console.debug(
            `HPKE envelope in transaction ${txn.id} failed discovery check, skipping...`,
          );
          continue;
        }

        console.debug(`Decrypting HPKE envelope for transaction ${txn.id}...`);
        const utxo = await UtxoSecrets.fromHpkeEnvelope(
          envelope,
          discoveryKeypair,
          txnMetadata,
        );

        console.debug(
          `Verifying commitment for UTXO from transaction ${txn.id}...`,
        );
        if (!method.verifyCommitment(utxo)) {
          console.debug(
            `UTXO commitment verification failed for transaction ${txn.id}, got commitment ${utxo.computeCommitment()} but expected one of ${method.commitments}`,
          );
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

        console.debug(`Adding ammount ${utxo.amount} from tx ${txn.id}`);
        this.amount += utxo.amount;
      }
    });
  }

  start() {
    this.subscriber.start();
  }
}
