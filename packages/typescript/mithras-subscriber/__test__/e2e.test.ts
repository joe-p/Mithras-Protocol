import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import { MithrasClient } from "../../mithras-contracts-and-circuits/contracts/clients/Mithras";

import { beforeAll, describe, expect, it } from "vitest";
import { Address } from "algosdk";
import { MithrasProtocolClient } from "../../mithras-contracts-and-circuits/src";
import {
  DiscoveryKeypair,
  getMerklePath,
  MithrasAddr,
  SpendSeed,
  SupportedHpkeSuite,
  bytesToNumberBE,
} from "../../mithras-crypto/src";
import { algodUtxoLookup, MithrasSubscriber } from "../src";

describe("Mithras App", () => {
  let appClient: MithrasClient;
  let algorand: AlgorandClient;
  let depositor: Address;
  let receiverDiscovery: DiscoveryKeypair;
  let receivedSpendSeed: SpendSeed;
  let receiver: MithrasAddr;
  let startRound: bigint;

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    depositor = await algorand.account.localNetDispenser();

    algorand.setSuggestedParamsCacheTimeout(0);

    const deployment = await MithrasProtocolClient.deploy(algorand, depositor);
    appClient = algorand.client.getTypedAppClientById(MithrasClient, {
      appId: deployment.appClient.appId,
      defaultSender: depositor,
    });

    receiverDiscovery = DiscoveryKeypair.generate();
    receivedSpendSeed = SpendSeed.generate();

    receiver = MithrasAddr.fromKeys(
      receivedSpendSeed.publicKey,
      receiverDiscovery.publicKey,
      1,
      0,
      SupportedHpkeSuite.x25519Sha256ChaCha20Poly1305,
    );

    startRound = (await algorand.client.algod.status().do()).lastRound;
  });

  it("deposit", async () => {
    const client = new MithrasProtocolClient(algorand, appClient.appId);

    const { group } = await client.composeDepositGroup(depositor, 1n, receiver);

    await group.send();

    const subscriber = new MithrasSubscriber(
      algorand.client.algod,
      appClient.appId,
      startRound,
      receiverDiscovery,
      receivedSpendSeed,
    );

    expect(subscriber.amount).toBe(0n);

    await subscriber.subscriber.pollOnce();

    expect(subscriber.amount).toBe(1n);

    const utxo = subscriber.utxos.entries().next().value;

    const utxoInfo = await algodUtxoLookup(
      algorand.client.algod,
      utxo[1],
      receiverDiscovery,
    );

    expect(utxoInfo.secrets.amount).toBe(1n);
    expect(utxoInfo.leafInfo.epochId).toBe(0n);
    expect(utxoInfo.leafInfo.treeIndex).toBe(0n);

    const zeroHashes = await appClient.state.box.zeroHashes();

    const path = getMerklePath(
      utxoInfo.leafInfo.leaf,
      utxoInfo.leafInfo.treeIndex,
      utxoInfo.leafInfo.subtree,
      zeroHashes!,
    );

    const contractRoot = (
      await appClient.state.global.lastComputedRoot()
    ).asByteArray();

    expect(path.root).toEqual(bytesToNumberBE(contractRoot!));
  });
});
