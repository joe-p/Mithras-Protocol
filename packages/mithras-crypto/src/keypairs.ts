import { mod } from "@noble/curves/abstract/modular.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  bytesToNumberLE,
  concatBytes,
  equalBytes,
  numberToBytesLE,
} from "@noble/curves/utils.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { MithrasAddr } from "./address";
import { SupportedHpkeSuite } from "./hpke";

export class DiscoveryKeypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;

  private constructor(privateKey: Uint8Array, publicKey: Uint8Array) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  static generate(): DiscoveryKeypair {
    const keypair = x25519.keygen();
    return new DiscoveryKeypair(keypair.secretKey, keypair.publicKey);
  }
}

function computePubkey(scalar: bigint): Uint8Array {
  const reducedScalar = mod(scalar, ed25519.Point.Fn.ORDER);

  // pubKey = scalar * G
  const publicKey = ed25519.Point.BASE.multiply(reducedScalar);
  return publicKey.toBytes();
}

export class SpendSeed {
  seed: Uint8Array;
  publicKey: Uint8Array;

  private constructor(seed: Uint8Array, publicKey: Uint8Array) {
    this.seed = seed;
    this.publicKey = publicKey;
    if (!equalBytes(publicKey, computePubkey(this.aScalar()))) {
      throw new Error("Public key does not match seed-derived public key");
    }
  }

  static generate(): SpendSeed {
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);

    const keypair = ed25519.keygen(seed);
    return new SpendSeed(seed, keypair.publicKey);
  }

  prefix(): Uint8Array {
    const hash = sha512(this.seed);
    return hash.slice(32, 64);
  }

  aScalar(): bigint {
    const hash = sha512(this.seed);
    const raw = bytesToNumberLE(hash.slice(0, 32));

    // Ed25519 scalar clamping: clear bits 0-2, set bit 254, clear bit 255
    const clamped = raw & ~((1n << 0n) | (1n << 1n) | (1n << 2n));
    const withBit254 = clamped | (1n << 254n);
    const clearedBit255 = withBit254 & ((1n << 255n) - 1n);

    return clearedBit255;
  }
}

const ORDER = ed25519.Point.CURVE().n; // subgroup order
const scalar = {
  add: (a: bigint, b: bigint) => {
    return (a + b) % ORDER;
  },
};

export class StealthKeypair {
  aScalar: Uint8Array;
  prefix: Uint8Array;
  publicKey: Uint8Array;

  constructor(aScalar: Uint8Array, prefix: Uint8Array, publicKey: Uint8Array) {
    this.aScalar = aScalar;
    this.prefix = prefix;
    this.publicKey = publicKey;
    if (!equalBytes(publicKey, computePubkey(bytesToNumberLE(aScalar)))) {
      throw new Error("Public key does not match aScalar-derived public key");
    }
  }

  static derive(spendSeed: SpendSeed, scalarToAdd: bigint): StealthKeypair {
    const stealthScalar = scalar.add(spendSeed.aScalar(), scalarToAdd);

    const stealthPrefix = sha512(
      concatBytes(numberToBytesLE(stealthScalar, 32), spendSeed.prefix()),
    );

    return new StealthKeypair(
      numberToBytesLE(stealthScalar, 32),
      stealthPrefix.slice(32, 64),
      deriveStealthPubkey(spendSeed.publicKey, scalarToAdd),
    );
  }

  rawSign(data: Uint8Array): Uint8Array {
    const scalar = bytesToNumberLE(this.aScalar);

    const kR = this.prefix;

    // (1): pubKey = scalar * G
    const publicKey = this.publicKey;

    // (2): h = hash(kR || msg) mod q
    const rHash = sha512(new Uint8Array([...kR, ...data]));
    const r = mod(bytesToNumberLE(rHash), ed25519.Point.Fn.ORDER);

    // (4): R = r * G
    const R = ed25519.Point.BASE.multiply(r);

    // h = hash(R || pubKey || msg) mod q
    const hHash = sha512(
      new Uint8Array([...R.toBytes(), ...publicKey, ...data]),
    );
    const h = mod(bytesToNumberLE(hHash), ed25519.Point.Fn.ORDER);

    // (5): S = (r + h * k) mod q
    const S = mod(r + h * scalar, ed25519.Point.Fn.ORDER);

    return new Uint8Array([...R.toBytes(), ...numberToBytesLE(S, 32)]);
  }
}

export function deriveStealthPubkey(
  basePublicKey: Uint8Array,
  stealthScalar: bigint,
): Uint8Array {
  const basePoint = ed25519.Point.fromBytes(basePublicKey);

  const tweakPoint = ed25519.Point.BASE.multiply(stealthScalar);
  const stealthPoint = basePoint.add(tweakPoint);

  return stealthPoint.toBytes();
}

export function deriveStealthScalar(discoverySecret: Uint8Array): bigint {
  const hash = sha512(
    concatBytes(
      new TextEncoder().encode("mithras-stealth-scalar"),
      discoverySecret,
    ),
  );
  return bytesToNumberLE(hash.slice(0, 32)) % ORDER;
}

export function deriveStealthPrefix(
  basePrefix: Uint8Array,
  stealthPublicKey: Uint8Array,
): Uint8Array {
  const hash = sha512(
    concatBytes(
      new TextEncoder().encode("mithras-stealth-prefix"),
      basePrefix,
      stealthPublicKey,
    ),
  );
  return hash.slice(32, 64);
}

export class MithrasAccount {
  spendSeed: SpendSeed;
  discoveryKeypair: DiscoveryKeypair;
  address: MithrasAddr;

  constructor(spendSeed: SpendSeed, discoveryKeypair: DiscoveryKeypair) {
    this.spendSeed = spendSeed;
    this.discoveryKeypair = discoveryKeypair;
    this.address = MithrasAddr.fromKeys(
      spendSeed.publicKey,
      discoveryKeypair.publicKey,
      1,
      0,
      SupportedHpkeSuite.x25519Sha256ChaCha20Poly1305,
    );
  }

  static generate(): MithrasAccount {
    return new MithrasAccount(
      SpendSeed.generate(),
      DiscoveryKeypair.generate(),
    );
  }
}
