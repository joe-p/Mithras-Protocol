import circom_tester from "circom_tester";
import { AlgorandClient } from "@algorandfoundation/algokit-utils/types/algorand-client";
import { microAlgos, Config } from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";

Config.configure({
  logger: {
    error: () => {},
    warn: () => {},
    info: () => {},
    verbose: () => {},
    debug: () => {},
  },
});

const wasm_tester = circom_tester.wasm;

export interface CircuitTestConfig {
  circuitPath: string;
  prime?: string;
  recompile?: boolean;
}

export interface MimcInput {
  msgs: [bigint, bigint];
}

export interface MerklePathInput {
  leaf: bigint;
  pathElements: bigint[];
  pathSelectors: number[];
  root: bigint;
}

export class CircuitTester {
  static async create(config: CircuitTestConfig) {
    return await wasm_tester(config.circuitPath, {
      prime: config.prime || "bls12381",
      recompile: config.recompile ?? true,
    });
  }

  static async createMimcTester() {
    return await this.create({
      circuitPath: "__test__/circuits/mimc.circom",
    });
  }

  static async createMerklePathTester() {
    return await this.create({
      circuitPath: "circuits/merkle_path_verify.circom",
    });
  }
}

export class AlgorandTestUtils {
  static createLocalClient(): AlgorandClient {
    return AlgorandClient.defaultLocalNet();
  }

  static async getDispenser(client: AlgorandClient) {
    return await client.account.localNetDispenser();
  }

  static generateRandomAppName(prefix: string): string {
    return `${prefix}-${Math.random().toString(36).substring(2, 15)}`;
  }

  static async fundAccount(
    client: AlgorandClient,
    address: algosdk.Address,
    amount: number,
  ) {
    await client.account.ensureFundedFromEnvironment(
      address,
      microAlgos(amount),
    );
  }
}

export class MimcCalculator {
  private circuit: any;

  constructor(circuit: any) {
    this.circuit = circuit;
  }

  static async create(): Promise<MimcCalculator> {
    const circuit = await CircuitTester.createMimcTester();
    return new MimcCalculator(circuit);
  }

  async calculateHash(left: bigint, right: bigint): Promise<bigint> {
    const witness = await this.circuit.calculateWitness({
      msgs: [left, right],
    });
    return witness[1];
  }

  async calculateMerkleRoot(
    leaf: bigint,
    pathElements: bigint[],
    pathSelectors: number[],
  ): Promise<bigint> {
    let currentHash = leaf;

    for (let i = 0; i < pathElements.length; i++) {
      const left = pathSelectors[i] === 0 ? currentHash : pathElements[i];
      const right = pathSelectors[i] === 0 ? pathElements[i] : currentHash;

      currentHash = await this.calculateHash(left, right);
    }

    return currentHash;
  }
}

export class MerkleTestHelpers {
  static createDefaultPathElements(size: number = 32): bigint[] {
    return new Array(size).fill(0n);
  }

  static createDefaultPathSelectors(size: number = 32): number[] {
    return new Array(size).fill(0);
  }

  static bytesToBigInt(bytes: Uint8Array): bigint {
    return BigInt("0x" + Buffer.from(bytes).toString("hex"));
  }

  static bigIntToBytes(value: bigint): Uint8Array {
    const hex = value.toString(16).padStart(64, "0");
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  static async verifyCircuitWithInput(
    circuit: any,
    input: MerklePathInput,
  ): Promise<void> {
    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  }
}

export class TestDataBuilder {
  static createMimcInput(left: bigint, right: bigint): MimcInput {
    return { msgs: [left, right] };
  }

  static createMerklePathInput(
    leaf: bigint,
    pathElements: bigint[] = MerkleTestHelpers.createDefaultPathElements(),
    pathSelectors: number[] = MerkleTestHelpers.createDefaultPathSelectors(),
    root: bigint = 0n,
  ): MerklePathInput {
    return { leaf, pathElements, pathSelectors, root };
  }

  static createTestLeaf(value: number): Uint8Array {
    const leaf = new Uint8Array(32);
    const bytes = [
      (value >> 24) & 0xff,
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff,
    ];
    leaf.set(bytes, 28);
    return leaf;
  }
}
