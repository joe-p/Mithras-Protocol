import { describe, expect, it } from "vitest";
import { initSync } from "../pkg/wasm-bindgen/index";
import {
  MithrasAddr,
  UtxoInputs,
  UtxoSecrets,
} from "../pkg/mithras_crypto_ffi";
import { readFileSync } from "fs";
import * as ed from "@noble/ed25519";
import nacl from "tweetnacl";
import { sha512 } from "@noble/hashes/sha2.js";
ed.hashes.sha512 = sha512;

const wasmFile = readFileSync("pkg/wasm-bindgen/index_bg.wasm");
initSync({ module: wasmFile });

function toArrayBuffer(uint8: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(uint8.length);
  new Uint8Array(ab).set(uint8);
  return ab;
}

describe("bindings", () => {
  it("should generate addr", () => {
    const addr = MithrasAddr.fromKeys(
      new ArrayBuffer(32),
      new ArrayBuffer(32),
      0,
      "custom",
      0,
    );

    expect(addr.encode()).toBe(
      "mith1qrlsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwjdn87",
    );
  });

  it("should generate utxo inputs and recover secrets", () => {
    const receiverSpendEd = ed.keygen();
    const receiverDiscovery = nacl.box.keyPair();

    const receiverAddr = MithrasAddr.fromKeys(
      toArrayBuffer(receiverSpendEd.publicKey),
      toArrayBuffer(receiverDiscovery.publicKey),
      0,
      "custom",
      0,
    );

    const senderEd = ed.keygen();

    const txnMetadata = {
      sender: toArrayBuffer(senderEd.publicKey),
      firstValid: 1n,
      lastValid: 50n,
      lease: new ArrayBuffer(32),
      network: "custom",
      appId: 1337n,
    };

    const inputs = UtxoInputs.generate(txnMetadata, 10n, receiverAddr);

    const recoveredSecrets = UtxoSecrets.fromHpkeEnvelope(
      inputs.envelope(),
      toArrayBuffer(receiverDiscovery.publicKey),
      toArrayBuffer(receiverDiscovery.secretKey),
      txnMetadata,
    );

    expect(recoveredSecrets.nullifierSecret()).toEqual(
      inputs.secrets().nullifierSecret(),
    );
    expect(recoveredSecrets.spendingSecret()).toEqual(
      inputs.secrets().spendingSecret(),
    );
  });
});
