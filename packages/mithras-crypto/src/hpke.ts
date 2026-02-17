import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { x25519 } from "@noble/curves/ed25519.js";
import { computeViewTag } from "./view";

export const CIPHER_TEXT_SIZE = 136 + 16; // SECRET_SIZE + AEAD tag
export const HPKE_SIZE = 1 + 1 + 32 + CIPHER_TEXT_SIZE + 32 + 32;
export const SupportedNetworks = {
  Mainnet: 0x00,
  Testnet: 0x01,
  Betanet: 0x02,
  Devnet: 0x03,
  Custom: 0xff,
} as const;

export class TransactionMetadata {
  sender: Uint8Array;
  firstValid: bigint;
  lastValid: bigint;
  lease: Uint8Array;
  network: number;
  appId: bigint;

  constructor(
    sender: Uint8Array,
    firstValid: bigint,
    lastValid: bigint,
    lease: Uint8Array,
    network: number,
    appId: bigint,
  ) {
    this.sender = sender;
    this.firstValid = firstValid;
    this.lastValid = lastValid;
    this.lease = lease;
    this.network = network;
    this.appId = appId;
  }

  info(): Uint8Array {
    return new TextEncoder().encode(
      `mithras|network:${this.network}|app:${this.appId}|v:1`,
    );
  }

  aad(): Uint8Array {
    const senderHex = Buffer.from(this.sender).toString("hex");
    const leaseHex = Buffer.from(this.lease).toString("hex");
    return new TextEncoder().encode(
      `txid:${senderHex}|fv:${this.firstValid}|lv:${this.lastValid}|lease:${leaseHex}`,
    );
  }
}

export enum SupportedHpkeSuite {
  x25519Sha256ChaCha20Poly1305 = 0x00,
}

export function getHpkeSuite(suite: SupportedHpkeSuite): CipherSuite {
  switch (suite) {
    case SupportedHpkeSuite.x25519Sha256ChaCha20Poly1305:
      return new CipherSuite({
        kem: new DhkemX25519HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Chacha20Poly1305(),
      });
    default:
      throw new Error(`Unsupported HPKE suite: ${suite}`);
  }
}

export class HpkeEnvelope {
  version: number;
  suite: SupportedHpkeSuite;
  encapsulatedKey: Uint8Array;
  ciphertext: Uint8Array;
  viewTag: Uint8Array;
  viewEphemeral: Uint8Array;

  constructor(
    version: number,
    suite: SupportedHpkeSuite,
    encapsulatedKey: Uint8Array,
    ciphertext: Uint8Array,
    viewTag: Uint8Array,
    viewEphemeral: Uint8Array,
  ) {
    this.version = version;
    this.suite = suite;
    this.encapsulatedKey = encapsulatedKey;
    this.ciphertext = ciphertext;
    this.viewTag = viewTag;
    this.viewEphemeral = viewEphemeral;
  }

  static fromBytes(data: Uint8Array): HpkeEnvelope {
    if (data.length !== HPKE_SIZE) {
      throw new Error(
        `Invalid HPKE envelope size: expected ${HPKE_SIZE}, got ${data.length}`,
      );
    }

    const version = data[0];
    const suite = data[1] as SupportedHpkeSuite;
    const encapsulatedKey = data.slice(2, 34);
    const ciphertext = data.slice(34, 34 + CIPHER_TEXT_SIZE);
    const viewTag = data.slice(
      34 + CIPHER_TEXT_SIZE,
      34 + CIPHER_TEXT_SIZE + 32,
    );
    const viewEphemeral = data.slice(34 + CIPHER_TEXT_SIZE + 32);

    return new HpkeEnvelope(
      version,
      suite,
      encapsulatedKey,
      ciphertext,
      viewTag,
      viewEphemeral,
    );
  }

  toBytes(): Uint8Array {
    const data = new Uint8Array(HPKE_SIZE);
    data[0] = this.version;
    data[1] = this.suite;
    data.set(this.encapsulatedKey, 2);
    data.set(this.ciphertext, 34);
    data.set(this.viewTag, 34 + CIPHER_TEXT_SIZE);
    data.set(this.viewEphemeral, 34 + CIPHER_TEXT_SIZE + 32);
    return data;
  }

  viewCheck(
    viewPrivate: Uint8Array,
    txnMetadata: TransactionMetadata,
  ): boolean {
    const viewSecret = x25519.getSharedSecret(viewPrivate, this.viewEphemeral);

    const computedTag = computeViewTag(
      viewSecret,
      txnMetadata.sender,
      txnMetadata.firstValid,
      txnMetadata.lastValid,
      txnMetadata.lease,
    );

    return Buffer.from(computedTag).equals(Buffer.from(this.viewTag));
  }
}
