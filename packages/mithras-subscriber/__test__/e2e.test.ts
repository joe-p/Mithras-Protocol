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
  MimcMerkleTree,
  MithrasAccount,
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
    const spenderKeypair = spender.spendKeypair;

    const { secrets, treeIndex } = await algodUtxoLookup(
      algorand.client.algod,
      utxo[1],
      spenderDisc,
    );

    const receiver = MithrasAccount.generate();

    const spendGroup = await client.composeSpendGroup(
      spender.address,
      spenderKeypair,
      secrets,
      spenderSubscriber.getMerkleProof(treeIndex),
      { receiver: receiver.address, amount },
    );

    // NOTE: There seems to be a bug with the signer for the lsig, for some reason the lsig txn is getting a ed25519 sig
    const innerComposer = await spendGroup.composer();
    const { atc } = await innerComposer.build();
    const txnsWithSigners = atc.buildGroup();
    txnsWithSigners[0]!.signer = (
      await client.spendVerifier.lsigAccount()
    ).signer;

    const composer = algorand.newGroup();
    composer.addAtc(atc);

    await composer.send();

    const receiversSubscriber = new MithrasSubscriber(
      algorand.client.algod,
      appClient.appId,
      startRound,
      receiver.discoveryKeypair,
      receiver.spendKeypair,
    );

    await receiversSubscriber.subscriber.pollOnce();

    expect(receiversSubscriber.amount).toBe(amount);

    return { receiver, receiversSubscriber };
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
    const initialReceiver = MithrasAccount.generate();
    const client = new MithrasProtocolClient(algorand, appClient.appId);

    const initialAmount = 1_000_000n;

    const { group: depositGroup } = await client.composeDepositGroup(
      depositor,
      initialAmount,
      initialReceiver.address,
    );

    await depositGroup.send();

    const subscriber = new MithrasSubscriber(
      algorand.client.algod,
      appClient.appId,
      startRound,
      initialReceiver.discoveryKeypair,
      initialReceiver.spendKeypair,
    );

    expect(subscriber.amount).toBe(0n);

    await subscriber.subscriber.pollOnce();

    expect(subscriber.amount).toBe(initialAmount);

    const utxo = subscriber.utxos.entries().next().value;

    const { secrets } = await algodUtxoLookup(
      algorand.client.algod,
      utxo[1],
      initialReceiver.discoveryKeypair,
    );

    expect(secrets.amount).toBe(initialAmount);

    const contractRoot = await appClient.state.global.lastComputedRoot();

    expect(contractRoot).toEqual(subscriber.getMerkleRoot());

    const mt = new MimcMerkleTree();

    mt.addLeaf(bytesToNumberBE(secrets.computeCommitment()));

    expect(mt.getRoot()).toEqual(contractRoot);

    const {
      receiver: secondReceiver,
      receiversSubscriber: secondReceiversSubscriber,
    } = await testSpend(
      client,
      initialReceiver,
      subscriber,
      initialAmount / 2n,
    );

    await testSpend(
      client,
      secondReceiver,
      secondReceiversSubscriber,
      initialAmount / 4n,
    );
  });
});
