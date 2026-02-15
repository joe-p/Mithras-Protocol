import {
  AlgorandClient,
  populateAppCallResources,
} from "@algorandfoundation/algokit-utils";
import { MithrasClient } from "../../mithras-contracts-and-circuits/contracts/clients/Mithras";

import { beforeAll, describe, expect, it } from "vitest";
import { Address } from "algosdk";
import { MithrasProtocolClient } from "../../mithras-contracts-and-circuits/src";
import {
  bytesToNumberBE,
  DiscoveryKeypair,
  MimcMerkleTree,
  MithrasAddr,
  SpendSeed,
  SupportedHpkeSuite,
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

  it("deposit and spend", async () => {
    const client = new MithrasProtocolClient(algorand, appClient.appId);

    const initialAmount = 500_000n;

    const { group: depositGroup } = await client.composeDepositGroup(
      depositor,
      initialAmount,
      receiver,
    );

    await depositGroup.send();

    const subscriber = new MithrasSubscriber(
      algorand.client.algod,
      appClient.appId,
      startRound,
      receiverDiscovery,
      receivedSpendSeed,
    );

    expect(subscriber.amount).toBe(0n);

    await subscriber.subscriber.pollOnce();

    expect(subscriber.amount).toBe(initialAmount);

    const utxo = subscriber.utxos.entries().next().value;

    const { secrets, treeIndex } = await algodUtxoLookup(
      algorand.client.algod,
      utxo[1],
      receiverDiscovery,
    );

    expect(secrets.amount).toBe(initialAmount);

    const contractRoot = await appClient.state.global.lastComputedRoot();

    const mt = new MimcMerkleTree();

    mt.addLeaf(bytesToNumberBE(secrets.computeCommitment()));

    expect(mt.getRoot()).toEqual(contractRoot);

    const secondReceiverSpendSeed = SpendSeed.generate();
    const secondReceiverDiscovery = DiscoveryKeypair.generate();

    const secondReceiver = MithrasAddr.fromKeys(
      secondReceiverSpendSeed.publicKey,
      secondReceiverDiscovery.publicKey,
      1,
      0,
      SupportedHpkeSuite.x25519Sha256ChaCha20Poly1305,
    );

    expect(contractRoot).toEqual(subscriber.getMerkleRoot());

    const spendGroup = await client.composeSpendGroup(
      receiver,
      receivedSpendSeed,
      secrets,
      subscriber.getMerkleProof(treeIndex),
      { receiver: secondReceiver, amount: initialAmount / 2n },
    );

    // NOTE: There seems to be a bug with the signer for the lsig, for some reason the lsig txn is getting a ed25519 sig
    const innerComposer = await spendGroup.composer();
    const { atc } = await innerComposer.build();
    const txnsWithSigners = atc.buildGroup();
    txnsWithSigners[0]!.signer = (
      await client.spendVerifier.lsigAccount()
    ).signer;

    const populated = await populateAppCallResources(
      atc,
      algorand.client.algod,
    );

    await populated.execute(algorand.client.algod, 3);

    const secondSubscriber = new MithrasSubscriber(
      algorand.client.algod,
      appClient.appId,
      startRound,
      secondReceiverDiscovery,
      secondReceiverSpendSeed,
    );

    await secondSubscriber.subscriber.pollOnce();

    expect(secondSubscriber.amount).toBe(initialAmount / 2n);
  });
});
