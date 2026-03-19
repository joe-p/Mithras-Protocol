import { beforeAll, describe, expect, test } from "vitest";
import {
  MimcMerkleTestFactory,
  MimcMerkleTestClient,
} from "./contracts/clients/MimcMerkleTest";
import { AlgorandClient, microAlgo } from "@algorandfoundation/algokit-utils";
import algosdk, { Address, LogicSigAccount } from "algosdk";
import { readFileSync } from "fs";
import { MimcMerkleTree } from "../../mithras-crypto/src/mimc";
import * as path from "path";
import { TREE_DEPTH } from "../src/constants";

async function emptyLsig(algorand: AlgorandClient): Promise<LogicSigAccount> {
  const lsigTeal = "#pragma version 12\nint 1";
  const compiled = await algorand.app.compileTealTemplate(lsigTeal, {});
  return algorand.account.logicsig(compiled.compiledBase64ToBytes).account;
}

describe("MiMC Merkle Contract Tests", () => {
  let client: MimcMerkleTestClient;
  let sender: Address;
  let lsig: LogicSigAccount;
  let algorand: AlgorandClient;
  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    sender = (await algorand.account.dispenserFromEnvironment()).addr;
    const factory = new MimcMerkleTestFactory({
      algorand,
      defaultSender: sender,
    });
    const lsigTeal = readFileSync(
      path.join(__dirname, "../contracts/out/mimc_merkle/CommitLeaf.teal"),
      "utf8",
    );

    const zeros = MimcMerkleTree.computeZeroHashes();
    const zerosEncoded = algosdk.ABIType.from(`uint256[${TREE_DEPTH}]`).encode(
      zeros,
    );

    const compiled = await algorand.app.compileTealTemplate(lsigTeal, {
      ZERO_HASHES: zerosEncoded,
    });
    lsig = algorand.account.logicsig(compiled.compiledBase64ToBytes).account;

    const { appClient } = await factory.deploy({
      appName: `MimcMerkleTest-${Date.now()}`,
      deployTimeParams: { ZERO_HASHES: zerosEncoded },
    });

    client = appClient;

    await algorand.account.ensureFundedFromEnvironment(
      client.appAddress,
      microAlgo(118900),
    );

    await client.send.bootstrapTest({
      args: { lsig: lsig.address().toString() },
      extraFee: microAlgo(256 * 1000),
    });
  });

  test("should add a leaf and commit it", async () => {
    const tree = new MimcMerkleTree();
    tree.addLeaf(0n); // epoch leaf

    const newLeaf = 123n;

    await client.send.addLeafTest({
      args: { leafHash: newLeaf, incentive: 0n },
    });

    const pendingLeaves = await client.state.box.pendingLeaves.getMap();
    expect(pendingLeaves.size).toBe(1);
    expect(pendingLeaves.get(newLeaf)).toEqual({ index: 1n, incentive: 0n });

    const rootCache = await client.state.box.rootCache.getMap();
    expect(rootCache.size).toBe(1);
    expect(rootCache.has(tree.getRoot())).toBe(true);

    const leafResult = tree.addLeaf(newLeaf);

    const extraLsig = await emptyLsig(algorand);

    const group = client.newGroup();
    for (let i = 0; i < 2; i++) {
      group.addTransaction(
        await algorand.createTransaction.payment({
          sender: extraLsig.address(),
          receiver: lsig.address(),
          amount: microAlgo(0),
          staticFee: microAlgo(0),
          note: new Uint8Array([i]), // to make the transactions different
        }),
      );
    }
    group.commitLeafTest({
      extraFee: microAlgo(3 * 1000),
      args: {
        lsigTxn: algorand.createTransaction.payment({
          sender: lsig.address(),
          receiver: lsig.address(),
          amount: microAlgo(0),
          staticFee: microAlgo(0),
        }),
        args: leafResult,
      },
    });

    await group.send();

    const pendingLeavesAfter = await client.state.box.pendingLeaves.getMap();
    expect(pendingLeavesAfter.size).toBe(0);

    const rootCacheAfter = await client.state.box.rootCache.getMap();
    expect(rootCacheAfter.size).toBe(2);
    expect(rootCacheAfter.has(tree.getRoot())).toBe(true);
  });
});
