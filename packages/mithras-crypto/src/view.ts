import { sha512_256 } from "@noble/hashes/sha2.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { numberToBytesLE } from "@noble/curves/utils.js";

export function computeViewSecretSender(
  ephemeralPrivate: Uint8Array,
  viewPublic: Uint8Array,
): Uint8Array {
  const sharedSecret = x25519.getSharedSecret(ephemeralPrivate, viewPublic);
  return sharedSecret;
}

export function computeViewSecretReceiver(
  viewPrivate: Uint8Array,
  ephemeralPublic: Uint8Array,
): Uint8Array {
  const sharedSecret = x25519.getSharedSecret(viewPrivate, ephemeralPublic);
  return sharedSecret;
}

export function computeViewTag(
  viewSecret: Uint8Array,
  sender: Uint8Array,
  fv: bigint,
  lv: bigint,
  lease: Uint8Array,
): Uint8Array {
  const hasher = sha512_256.create();
  hasher.update(new TextEncoder().encode("view-tag"));
  hasher.update(viewSecret);
  hasher.update(sender);
  hasher.update(numberToBytesLE(fv, 8));
  hasher.update(numberToBytesLE(lv, 8));
  hasher.update(lease);
  return hasher.digest();
}
