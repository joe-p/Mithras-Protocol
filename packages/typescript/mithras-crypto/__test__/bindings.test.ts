import { describe, expect, it } from "vitest";
import { initSync } from "../pkg/wasm-bindgen/index";
import { MithrasAddr, UtxoInputs } from "../pkg/mithras_crypto_ffi";
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

  it("should generate utxo inputs", () => {
    const receiverSpendEd = ed.keygen();
    const receiverDiscovery = nacl.box.keyPair();

    const addr = MithrasAddr.fromKeys(
      toArrayBuffer(receiverSpendEd.publicKey),
      toArrayBuffer(receiverDiscovery.publicKey),
      0,
      "custom",
      0,
    );

    const senderEd = ed.keygen();
    const inputs = UtxoInputs.generate(
      {
        sender: toArrayBuffer(senderEd.publicKey),
        firstValid: 1n,
        lastValid: 50n,
        lease: new ArrayBuffer(32),
        network: "custom",
        appId: 1337n,
      },
      10n,
      addr,
    );

    expect(inputs.envelope()).toBeDefined();
    expect(inputs.secrets()).toBeDefined();
  });
});
