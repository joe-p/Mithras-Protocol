import { AlgorandSubscriber } from "@algorandfoundation/algokit-subscriber";
import {
  AlgorandSubscriberConfig,
  TransactionFilter,
} from "@algorandfoundation/algokit-subscriber/types/subscription";
import algosdk from "algosdk";
import {
  DiscoveryKeypair,
  HpkeEnvelope,
  MerkleProof as MerkleProof,
  MimcMerkleTree,
  SpendKeypair,
  TransactionMetadata,
  StealthKeypair,
  UtxoSecrets,
} from "../../mithras-crypto/src";
import base32 from "hi-base32";

import appspec from "../../mithras-contracts-and-circuits/contracts/out/Mithras.arc56.json";

const DEPOSIT_SIGNATURE =
  "deposit(uint256[],(byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],uint256,uint256,uint256,uint256,uint256,uint256),byte[250],pay,txn)void";
const SPEND_SIGNATURE =
  "spend(uint256[],(byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],uint256,uint256,uint256,uint256,uint256,uint256),byte[250],byte[250],txn)void";

const DEPOSIT_SELECTOR =
  algosdk.ABIMethod.fromSignature(DEPOSIT_SIGNATURE).getSelector();
const SPEND_SELECTOR =
  algosdk.ABIMethod.fromSignature(SPEND_SIGNATURE).getSelector();

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
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
  firstCommitment: boolean;
};

export async function algodUtxoLookup(
  algod: algosdk.Algodv2,
  info: UtxoInfo,
  discvoveryKeypair: DiscoveryKeypair,
): Promise<{ secrets: UtxoSecrets; treeIndex: number }> {
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

  const txn = transaction?.signedTxn.signedTxn.txn!;

  const txnMetadata = new TransactionMetadata(
    txn.sender.publicKey!,
    txn.firstValid,
    txn.lastValid,
    txn.lease ?? new Uint8Array(32),
    0, // TODO: handle network ID
    appl?.appIndex!,
  );

  const delta = transaction?.signedTxn.applyData.evalDelta?.globalDelta;
  const key = new TextEncoder().encode("i");

  let treeIndex: number | null = null;

  for (const [k, v] of delta ?? []) {
    if (equalBytes(k, key)) {
      treeIndex = Number(v.uint);
    }
  }

  if (treeIndex === null) {
    throw new Error(
      `Failed to find index in global delta for UTXO lookup: ${delta}`,
    );
  }

  // The index in the global state delta is the next index to be used. This means that for a deposit (one commitment leaf), we need to subtract one. For a spend (two commitment leaves, thus two increments), we need to first know whether or not we are spending the first or second commitment (out0 vs out1) and then subtract either one or two.
  if (method.type === "spend" && info.firstCommitment) {
    treeIndex -= 2;
  } else {
    treeIndex -= 1;
  }
  const hpkeEnv = method.hpke_envelopes[info.firstCommitment ? 0 : 1];

  const secrets = await UtxoSecrets.fromHpkeEnvelope(
    hpkeEnv,
    discvoveryKeypair,
    txnMetadata,
  );

  return {
    secrets,
    treeIndex,
  };
}

export type BalanceSubscriberConfig = {
  discoveryKeypair: DiscoveryKeypair;
  spendKeypair: SpendKeypair;
};

export type MerkleTreeSubscriberConfig = {
  merkleTree?: MimcMerkleTree;
};

export type BalanceAndTreeSubscriberConfig = BalanceSubscriberConfig &
  MerkleTreeSubscriberConfig;

type BalanceState = {
  amount: bigint;
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
  utxos: Map<Uint8Array, UtxoInfo>;
};

type BaseSubscriberConfig = {
  appId: bigint;
  algod: algosdk.Algodv2;
  startRound?: bigint;
};

type BaseSubscriberOptions = {
  algod: algosdk.Algodv2;
  appId: bigint;
  startRound: bigint;
  discoveryKeypair?: DiscoveryKeypair;
  spendKeypair?: SpendKeypair;
  merkleTree?: MimcMerkleTree;
  balanceState?: BalanceState;
};

async function resolveStartRound(config: {
  appId: bigint;
  algod: algosdk.Algodv2;
  startRound?: bigint;
  merkleTree?: MimcMerkleTree;
}): Promise<bigint> {
  const { appId, algod } = config;

  if (config.startRound === undefined) {
    if (config.merkleTree && config.merkleTree.getLeafCount() > 0) {
      throw new Error(
        "When starting the subscriber with a pre-constructed Merkle tree, the startRound must be provided",
      );
    }

    let creationRound: bigint | undefined = undefined;
    for (const g of (await algod.getApplicationByID(appId).do()).params
      .globalState ?? []) {
      console.debug(g);
      if (new TextDecoder().decode(g.key) === "c") {
        // TODO: For some reason on localnet this always seems to be 1
        creationRound = BigInt(g.value.uint);
        console.debug(
          `Found creation round ${creationRound} in application global state`,
        );
        break;
      }
    }

    if (creationRound === undefined) {
      throw new Error(
        "Failed to find creation round in application global state",
      );
    }
  }

  return config.startRound ?? 0n;
}

class BaseMithrasSubscriber {
  public subscriber: AlgorandSubscriber;
  protected merkleTree?: MimcMerkleTree;
  protected balanceState?: BalanceState;

  protected constructor(options: BaseSubscriberOptions) {
    const {
      algod,
      appId,
      startRound,
      discoveryKeypair,
      spendKeypair,
      merkleTree,
      balanceState,
    } = options;
    let watermark = startRound;

    this.merkleTree = merkleTree;
    this.balanceState = balanceState;

    const filter: TransactionFilter = {
      appId,
      methodSignature: [DEPOSIT_SIGNATURE, SPEND_SIGNATURE],
      arc28Events: [{ groupName: "mithras", eventName: "NewLeaf" }],
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
      arc28Events: [
        {
          groupName: "mithras",
          events: appspec.events,
        },
      ],
    };
    this.subscriber = new AlgorandSubscriber(config, algod);

    this.subscriber.on("mithras", async (txn) => {
      console.debug(
        `Processing transaction ${txn.id} in round ${txn.confirmedRound}`,
      );

      if (this.merkleTree) {
        for (const event of txn.arc28Events!) {
          const { leaf } = event.argsByName;
          this.merkleTree.addLeaf(leaf as bigint);
        }
      }

      if (
        balanceState === undefined ||
        discoveryKeypair === undefined ||
        spendKeypair === undefined
      ) {
        console.debug(
          "No discovery or spend keypair provided, skipping transaction processing",
        );
        return;
      }

      const appl = txn.applicationTransaction!;

      const method = MithrasMethod.fromArgs(appl.applicationArgs!);

      if (method === null) {
        console.debug(`Failed to parse method from transaction ${txn.id}`);
        return;
      }

      if (method.type === "spend") {
        if (balanceState.utxos.has(method.nullifier!)) {
          const { amount } = balanceState.utxos.get(method.nullifier!)!;
          balanceState.amount -= algosdk.decodeUint64(amount, "bigint");
          balanceState.utxos.delete(method.nullifier!);
          return;
        }
      }

      let firstCommitment = false;
      for (const envelope of method.hpke_envelopes) {
        firstCommitment = !firstCommitment;
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
        if (balanceState.utxos.has(nullifier)) {
          continue;
        } else {
          balanceState.utxos.set(nullifier, {
            round: algosdk.encodeUint64(txn.confirmedRound ?? 0n),
            amount: algosdk.encodeUint64(utxo.amount),
            txid: new Uint8Array(base32.decode.asBytes(txn.id)),
            firstCommitment,
          });
        }

        const derivedSigner = StealthKeypair.derive(
          spendKeypair,
          utxo.stealthScalar,
        );

        if (
          derivedSigner.publicKey.toString() != utxo.stealthPubkey.toString()
        ) {
          continue;
        }

        console.debug(`Adding ammount ${utxo.amount} from tx ${txn.id}`);
        balanceState.amount += utxo.amount;
      }
    });
  }
}

export class BalanceSubscriber extends BaseMithrasSubscriber {
  public static async fromAppId(
    config: BaseSubscriberConfig & BalanceSubscriberConfig,
  ) {
    const startRound = await resolveStartRound({
      appId: config.appId,
      algod: config.algod,
      startRound: config.startRound,
    });

    return new BalanceSubscriber(
      config.algod,
      config.appId,
      startRound,
      config.discoveryKeypair,
      config.spendKeypair,
    );
  }

  public constructor(
    algod: algosdk.Algodv2,
    appId: bigint,
    startRound: bigint,
    discoveryKeypair: DiscoveryKeypair,
    spendKeypair: SpendKeypair,
  ) {
    const balanceState: BalanceState = {
      amount: 0n,
      utxos: new Map(),
    };
    super({
      algod,
      appId,
      startRound,
      discoveryKeypair,
      spendKeypair,
      balanceState,
    });
    this.balanceState = balanceState;
  }

  public get amount(): bigint {
    return this.balanceState!.amount;
  }

  public set amount(value: bigint) {
    this.balanceState!.amount = value;
  }

  public get utxos(): Map<Uint8Array, UtxoInfo> {
    return this.balanceState!.utxos;
  }
}

export class TreeSubscriber extends BaseMithrasSubscriber {
  public merkleTree: MimcMerkleTree;

  public static async fromAppId(
    config: BaseSubscriberConfig & MerkleTreeSubscriberConfig,
  ) {
    const startRound = await resolveStartRound({
      appId: config.appId,
      algod: config.algod,
      startRound: config.startRound,
      merkleTree: config.merkleTree,
    });

    return new TreeSubscriber(
      config.algod,
      config.appId,
      startRound,
      config.merkleTree ?? new MimcMerkleTree(),
    );
  }

  public constructor(
    algod: algosdk.Algodv2,
    appId: bigint,
    startRound: bigint,
    merkleTree: MimcMerkleTree,
  ) {
    super({
      algod,
      appId,
      startRound,
      merkleTree,
    });
    this.merkleTree = merkleTree;
  }
}

export class BalanceAndTreeSubscriber extends BaseMithrasSubscriber {
  public merkleTree: MimcMerkleTree;

  public static async fromAppId(
    config: BaseSubscriberConfig & BalanceAndTreeSubscriberConfig,
  ) {
    const startRound = await resolveStartRound({
      appId: config.appId,
      algod: config.algod,
      startRound: config.startRound,
      merkleTree: config.merkleTree,
    });

    return new BalanceAndTreeSubscriber(
      config.algod,
      config.appId,
      startRound,
      config.discoveryKeypair,
      config.spendKeypair,
      config.merkleTree ?? new MimcMerkleTree(),
    );
  }

  public constructor(
    algod: algosdk.Algodv2,
    appId: bigint,
    startRound: bigint,
    discoveryKeypair: DiscoveryKeypair,
    spendKeypair: SpendKeypair,
    merkleTree: MimcMerkleTree,
  ) {
    const balanceState: BalanceState = {
      amount: 0n,
      utxos: new Map(),
    };
    super({
      algod,
      appId,
      startRound,
      discoveryKeypair,
      spendKeypair,
      merkleTree,
      balanceState,
    });
    this.balanceState = balanceState;
    this.merkleTree = merkleTree;
  }

  public get amount(): bigint {
    return this.balanceState!.amount;
  }

  public set amount(value: bigint) {
    this.balanceState!.amount = value;
  }

  public get utxos(): Map<Uint8Array, UtxoInfo> {
    return this.balanceState!.utxos;
  }
}
