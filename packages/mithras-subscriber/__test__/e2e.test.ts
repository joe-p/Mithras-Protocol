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
  MithrasAccount,
  MithrasAddr,
  SpendSeed,
  SupportedHpkeSuite,
} from "../../mithras-crypto/src";
import { algodUtxoLookup, MithrasSubscriber } from "../src";

describe("Mithras App", () => {
  let appClient: MithrasClient;
  let algorand: AlgorandClient;
  let depositor: Address;

  let startRound: bigint;

  const testSpend = async (
    client: MithrasProtocolClient,
    spender: MithrasAccount,
    spenderSubscriber: MithrasSubscriber,
    amount: bigint,
  ) => {
    const utxo = spenderSubscriber.utxos.entries().next().value;
    const spenderDisc = spender.discoveryKeypair;
    const spenderSeed = spender.spendSeed;

    const { secrets, treeIndex } = await algodUtxoLookup(
      algorand.client.algod,
      utxo[1],
      spenderDisc,
    );

    const secondReceiverSpendSeed = SpendSeed.generate();
    const secondReceiverDiscovery = DiscoveryKeypair.generate();

    const secondReceiver = MithrasAddr.fromKeys(
      secondReceiverSpendSeed.publicKey,
      secondReceiverDiscovery.publicKey,
      1,
      0,
      SupportedHpkeSuite.x25519Sha256ChaCha20Poly1305,
    );

    const spendGroup = await client.composeSpendGroup(
      spender.address,
      spenderSeed,
      secrets,
      spenderSubscriber.getMerkleProof(treeIndex),
      { receiver: secondReceiver, amount },
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

    expect(secondSubscriber.amount).toBe(amount);
  };

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    depositor = await algorand.account.localNetDispenser();

    algorand.setSuggestedParamsCacheTimeout(0);

    const deployment = await MithrasProtocolClient.deploy(algorand, depositor);
    appClient = algorand.client.getTypedAppClientById(MithrasClient, {
      appId: deployment.appClient.appId,
      defaultSender: depositor,
    });

    startRound = (await algorand.client.algod.status().do()).lastRound;
  });

  it("deposit and spend", async () => {
    const receiver = MithrasAccount.generate();
    const client = new MithrasProtocolClient(algorand, appClient.appId);

    const initialAmount = 500_000n;

    const { group: depositGroup } = await client.composeDepositGroup(
      depositor,
      initialAmount,
      receiver.address,
    );

    await depositGroup.send();

    const subscriber = new MithrasSubscriber(
      algorand.client.algod,
      appClient.appId,
      startRound,
      receiver.discoveryKeypair,
      receiver.spendSeed,
    );

    expect(subscriber.amount).toBe(0n);

    await subscriber.subscriber.pollOnce();

    expect(subscriber.amount).toBe(initialAmount);

    const utxo = subscriber.utxos.entries().next().value;

    const { secrets } = await algodUtxoLookup(
      algorand.client.algod,
      utxo[1],
      receiver.discoveryKeypair,
    );

    expect(secrets.amount).toBe(initialAmount);

    const contractRoot = await appClient.state.global.lastComputedRoot();

    expect(contractRoot).toEqual(subscriber.getMerkleRoot());

    const mt = new MimcMerkleTree();

    mt.addLeaf(bytesToNumberBE(secrets.computeCommitment()));

    expect(mt.getRoot()).toEqual(contractRoot);

    await testSpend(client, receiver, subscriber, initialAmount / 2n);
  });
});
