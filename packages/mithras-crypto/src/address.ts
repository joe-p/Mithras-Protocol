import { bech32 } from "bech32";

export class MithrasAddr {
  version: number;
  network: number;
  suite: number;
  spendEd25519: Uint8Array;
  viewX25519: Uint8Array;

  constructor(
    version: number,
    network: number,
    suite: number,
    spendEd25519: Uint8Array,
    viewX25519: Uint8Array,
  ) {
    this.version = version;
    this.network = network;
    this.suite = suite;

    if (spendEd25519.length !== 32) {
      throw new Error(
        `invalid spendEd25519 length. Got ${spendEd25519.length}, expected 32`,
      );
    }
    if (viewX25519.length !== 32) {
      throw new Error(
        `invalid viewX25519 length. Got ${viewX25519.length}, expected 32`,
      );
    }

    this.spendEd25519 = spendEd25519;
    this.viewX25519 = viewX25519;
  }

  static fromKeys(
    spend: Uint8Array,
    view: Uint8Array,
    version: number,
    network: number,
    suite: number,
  ): MithrasAddr {
    return new MithrasAddr(version, network, suite, spend, view);
  }

  encode(): string {
    const data = new Uint8Array(3 + 32 + 32);
    data[0] = this.version;
    data[1] = this.network;
    data[2] = this.suite;
    data.set(this.spendEd25519, 3);
    data.set(this.viewX25519, 35);

    return bech32.encode("mith", bech32.toWords(data), 200);
  }

  static decode(s: string): MithrasAddr {
    const { prefix, words } = bech32.decode(s, 200);
    if (prefix !== "mith") {
      throw new Error(
        `invalid human-readable prefix. Got ${prefix}, expected mith`,
      );
    }
    const data = new Uint8Array(bech32.fromWords(words));
    const version = data[0];
    const network = data[1];
    const suite = data[2];
    const spend = data.slice(3, 35);
    const view = data.slice(35, 67);

    return new MithrasAddr(version, network, suite, spend, view);
  }
}
