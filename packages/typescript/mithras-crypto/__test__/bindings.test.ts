import { describe, expect, it } from "vitest";
import { initSync } from "../pkg/wasm-bindgen/index";
import { MithrasAddr, UtxoInputs } from "../pkg/mithras_crypto_ffi";
import { readFileSync } from "fs";

const wasmFile = readFileSync("pkg/wasm-bindgen/index_bg.wasm");
initSync({ module: wasmFile });

describe("bindings", () => {
  it("should generate addr", async () => {
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

  it("should generate utxo inputs", async () => {
    const addr = MithrasAddr.fromKeys(
      new ArrayBuffer(32),
      new ArrayBuffer(32),
      0,
      "custom",
      0,
    );

    // FIXME: currently panics, need to use Result instead of panics
    const inputs = UtxoInputs.generate(
      {
        sender: new ArrayBuffer(32),
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
