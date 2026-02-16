import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils.js";
import {
  getHpkeSuite,
  HpkeEnvelope,
  SupportedHpkeSuite,
  TransactionMetadata,
} from "./hpke";
import {
  deriveStealthPubkey,
  deriveStealthScalar,
  DiscoveryKeypair,
} from "./keypairs";
import { computeDiscoverySecretSender, computeDiscoveryTag } from "./discovery";
import { MithrasAddr } from "./address";
import { mimcSum } from "./mimc";
import { addressInScalarField } from "../../mithras-contracts-and-circuits/src";

export const SECRET_SIZE: number = 136;

export class UtxoSecrets {
  spendingSecret: Uint8Array;
  nullifierSecret: Uint8Array;
  amount: bigint;
  stealthScalar: bigint;
  stealthPubkey: Uint8Array;

  constructor(
    spendingSecret: Uint8Array,
    nullifierSecret: Uint8Array,
    amount: bigint,
    stealthScalar: bigint,
    stealthPubkey: Uint8Array,
  ) {
    this.spendingSecret = spendingSecret;
    this.nullifierSecret = nullifierSecret;
    this.amount = amount;
    this.stealthScalar = stealthScalar;
    this.stealthPubkey = stealthPubkey;
  }

  static fromBytes(bytes: Uint8Array): UtxoSecrets {
    if (bytes.length !== SECRET_SIZE) {
      throw new Error(
        `Invalid byte array length for UtxoSecrets: expected ${SECRET_SIZE}, got ${bytes.length}`,
      );
    }

    const spendingSecret = bytes.slice(0, 32);
    const nullifierSecret = bytes.slice(32, 64);
    const amount = bytesToNumberBE(bytes.slice(64, 72));
    const stealthScalar = bytesToNumberBE(bytes.slice(72, 104));
    const stealthPubkey = bytes.slice(104, 136);

    return new UtxoSecrets(
      spendingSecret,
      nullifierSecret,
      amount,
      stealthScalar,
      stealthPubkey,
    );
  }

  toBytes(): Uint8Array {
    const bytes = new Uint8Array(SECRET_SIZE);
    bytes.set(this.spendingSecret, 0);
    bytes.set(this.nullifierSecret, 32);
    bytes.set(numberToBytesBE(this.amount, 8), 64);
    bytes.set(numberToBytesBE(this.stealthScalar, 32), 72);
    bytes.set(this.stealthPubkey, 104);
    return bytes;
  }

  static async fromHpkeEnvelope(
    hpkeEnvelope: HpkeEnvelope,
    discoveryKeypair: DiscoveryKeypair,
    txnMetadata: TransactionMetadata,
  ): Promise<UtxoSecrets> {
    const hpke = getHpkeSuite(hpkeEnvelope.suite);

    const recvCtx = await hpke.createRecipientContext({
      recipientKey: await hpke.kem.deserializePrivateKey(
        discoveryKeypair.privateKey,
      ),
      enc: hpkeEnvelope.encapsulatedKey,
      info: txnMetadata.info(),
    });

    const plaintext = await recvCtx.open(
      hpkeEnvelope.ciphertext,
      txnMetadata.aad(),
    );

    return UtxoSecrets.fromBytes(new Uint8Array(plaintext));
  }

  computeCommitment(): Uint8Array {
    const input = [
      bytesToNumberBE(this.spendingSecret),
      bytesToNumberBE(this.nullifierSecret),
      this.amount,
      addressInScalarField(this.stealthPubkey),
    ];
    return numberToBytesBE(mimcSum(input), 32);
  }

  computeNullifier(): Uint8Array {
    const commitment = this.computeCommitment();
    return numberToBytesBE(
      mimcSum([
        bytesToNumberBE(commitment),
        bytesToNumberBE(this.nullifierSecret),
      ]),
      32,
    );
  }
}

export class UtxoInputs {
  secrets: UtxoSecrets;
  hpkeEnvelope: HpkeEnvelope;

  private constructor(secrets: UtxoSecrets, hpkeEnvelope: HpkeEnvelope) {
    this.secrets = secrets;
    this.hpkeEnvelope = hpkeEnvelope;
  }

  static async generate(
    txnMetadata: TransactionMetadata,
    amount: bigint,
    receiver: MithrasAddr,
  ): Promise<UtxoInputs> {
    const hpke = getHpkeSuite(SupportedHpkeSuite.x25519Sha256ChaCha20Poly1305);

    const ephemeralKeypair = DiscoveryKeypair.generate();

    const discoverySecret = computeDiscoverySecretSender(
      ephemeralKeypair.privateKey,
      receiver.discX25519,
    );

    const stealthScalar = deriveStealthScalar(discoverySecret);
    const stealthPubkey = deriveStealthPubkey(
      receiver.spendEd25519,
      stealthScalar,
    );

    const discoveryTag = computeDiscoveryTag(
      discoverySecret,
      txnMetadata.sender,
      txnMetadata.firstValid,
      txnMetadata.lastValid,
      txnMetadata.lease,
    );

    const spendingSecret = crypto.getRandomValues(new Uint8Array(32));
    const nullifierSecret = crypto.getRandomValues(new Uint8Array(32));

    const mithrasSecret = new UtxoSecrets(
      spendingSecret,
      nullifierSecret,
      amount,
      stealthScalar,
      stealthPubkey,
    );

    const senderCtx = await hpke.createSenderContext({
      recipientPublicKey: await hpke.kem.deserializePublicKey(
        receiver.discX25519,
      ),
      info: txnMetadata.info(),
    });

    const ct = await senderCtx.seal(mithrasSecret.toBytes(), txnMetadata.aad());

    const hpkeEnvelope = new HpkeEnvelope(
      1,
      SupportedHpkeSuite.x25519Sha256ChaCha20Poly1305,
      new Uint8Array(senderCtx.enc),
      new Uint8Array(ct),
      discoveryTag,
      ephemeralKeypair.publicKey,
    );

    return new UtxoInputs(mithrasSecret, hpkeEnvelope);
  }
}
