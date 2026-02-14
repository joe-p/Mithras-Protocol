import { ed25519 } from "@noble/curves/ed25519.js";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  bytesToNumberLE,
  concatBytes,
  numberToBytesLE,
} from "@noble/curves/utils.js";
import { sha512 } from "@noble/hashes/sha2.js";

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

export class SpendSeed {
  seed: Uint8Array;
  publicKey: Uint8Array;

  private constructor(seed: Uint8Array, publicKey: Uint8Array) {
    this.seed = seed;
    this.publicKey = publicKey;
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
    return bytesToNumberLE(hash.slice(0, 32));
  }
}

const ORDER = ed25519.Point.CURVE().n; // subgroup order
const scalar = {
  add: (a: bigint, b: bigint) => {
    return (a + b) % ORDER;
  },
};

export class TweakedSigner {
  aScalar: Uint8Array;
  prefix: Uint8Array;
  publicKey: Uint8Array;

  constructor(aScalar: Uint8Array, prefix: Uint8Array, publicKey: Uint8Array) {
    this.aScalar = aScalar;
    this.prefix = prefix;
    this.publicKey = publicKey;
  }

  derive(spendSeed: SpendSeed, tweakScalar: bigint): TweakedSigner {
    const tweakedScalar = scalar.add(spendSeed.aScalar(), tweakScalar);

    const tweakdPrefix = sha512(
      concatBytes(numberToBytesLE(tweakScalar, 32), spendSeed.prefix()),
    );

    return new TweakedSigner(
      numberToBytesLE(tweakedScalar, 32),
      tweakdPrefix.slice(32, 64),
      deriveTweakedPubkey(spendSeed.publicKey, tweakScalar),
    );
  }
}

export function deriveTweakedPubkey(
  basePublicKey: Uint8Array,
  tweakScalar: bigint,
): Uint8Array {
  const basePoint = ed25519.Point.fromBytes(basePublicKey);

  const tweakPoint = ed25519.Point.BASE.multiply(tweakScalar);
  const stealthPoint = basePoint.add(tweakPoint);

  return stealthPoint.toBytes();
}

export function deriveTweakScalar(discoverySecret: Uint8Array): bigint {
  const hash = sha512(
    concatBytes(
      new TextEncoder().encode("mithras-tweak-scalar"),
      discoverySecret,
    ),
  );
  return bytesToNumberLE(hash.slice(0, 32)) % ORDER;
}

export function deriveTweakedPrefix(
  basePrefix: Uint8Array,
  tweakedPublicKey: Uint8Array,
): Uint8Array {
  const hash = sha512(
    concatBytes(
      new TextEncoder().encode("mithras-tweaked-prefix"),
      basePrefix,
      tweakedPublicKey,
    ),
  );
  return hash.slice(32, 64);
}
