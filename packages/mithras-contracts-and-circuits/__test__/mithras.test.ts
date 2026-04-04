import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import { MithrasClient } from "../contracts/clients/Mithras";

import { beforeEach, describe, expect, it } from "vitest";
import { MimcCalculator } from "./utils/test-utils";
import { Address } from "algosdk";
import { composeCommitUtxoGroup, MithrasProtocolClient } from "../src";
import {
  ViewKeypair,
  MithrasAddr,
  SpendKeypair,
  SupportedHpkeSuite,
  MimcMerkleTree,
  MithrasAccount,
} from "../../mithras-crypto/src";

describe("Mithras App", () => {
  let appClient: MithrasClient;
  let algorand: AlgorandClient;
  let mimcCalculator: MimcCalculator;
  let depositor: Address;
  let spender: Address;

  beforeEach(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    depositor = await algorand.account.localNetDispenser();
    spender = algorand.account.random();

    algorand.setSuggestedParamsCacheTimeout(0);
    mimcCalculator = await MimcCalculator.create();

    const deployment = await MithrasProtocolClient.deploy(algorand, depositor);
    appClient = algorand.client.getTypedAppClientById(MithrasClient, {
      appId: deployment.appClient.appId,
      defaultSender: depositor,
    });
  });

  it("deposit", async () => {
    const client = new MithrasProtocolClient(algorand, appClient.appId);
    const tree = new MimcMerkleTree();
    tree.addLeaf(0n);

    const preRoot = await appClient.state.global.currentRoot();
    expect(preRoot).toBe(tree.getRoot());

    const { group, utxoCommitment } = await client.composeDepositGroup(
      depositor,
      1n,
      MithrasAddr.fromKeys(
        SpendKeypair.generate().publicKey,
        ViewKeypair.generate().publicKey,
        1,
        0,
        SupportedHpkeSuite.x25519Sha256ChaCha20Poly1305,
      ),
    );

    const simRes = await group.simulate({
      allowUnnamedResources: true,
    });

    expect(
      simRes.simulateResponse.txnGroups[0].appBudgetConsumed,
    ).toMatchSnapshot("deposit app budget");

    await group.send();

    const commitArgs = tree.addLeaf(utxoCommitment);

    // Verify the leaf was added to pendingLeaves but the root hasn't been updated yet since we haven't committed
    const pendingLeaves = await appClient.state.box.pendingLeaves.getMap();
    expect(pendingLeaves.size).toBe(1);
    expect(pendingLeaves.get(utxoCommitment)).toEqual({
      index: 1n,
      incentive: 0n,
    });
    expect(await appClient.state.global.currentRoot()).toBe(preRoot);

    // Now commit the leaf and ensure the root is updated and pendingLeaves is cleared
    const commitGroup = await composeCommitUtxoGroup(
      algorand,
      appClient.appId,
      depositor,
      commitArgs,
    );

    await commitGroup.send();

    const postRoot = await appClient.state.global.currentRoot();
    expect(postRoot).not.toBe(preRoot);
    expect(postRoot).toBe(tree.getRoot());

    expect(await appClient.state.box.pendingLeaves.getMap()).toEqual(new Map());
  });

  it("spend", async () => {
    const client = new MithrasProtocolClient(algorand, appClient.appId);
    const tree = new MimcMerkleTree();
    tree.addLeaf(0n);

    const spender = MithrasAccount.generate();
    const preRoot = await appClient.state.global.currentRoot();
    expect(preRoot).toBe(tree.getRoot());

    const { group, utxoCommitment, utxoInputs } =
      await client.composeDepositGroup(depositor, 1_000_000n, spender.address);

    await group.send();

    const commitArgs = tree.addLeaf(utxoCommitment);

    // Verify the leaf was added to pendingLeaves but the root hasn't been updated yet since we haven't committed
    const pendingLeaves = await appClient.state.box.pendingLeaves.getMap();
    expect(pendingLeaves.size).toBe(1);
    expect(pendingLeaves.get(utxoCommitment)).toEqual({
      index: 1n,
      incentive: 0n,
    });
    expect(await appClient.state.global.currentRoot()).toBe(preRoot);

    // Now commit the leaf and ensure the root is updated and pendingLeaves is cleared
    const commitGroup = await composeCommitUtxoGroup(
      algorand,
      appClient.appId,
      depositor,
      commitArgs,
    );

    await commitGroup.send();

    const postRoot = await appClient.state.global.currentRoot();
    expect(postRoot).not.toBe(preRoot);
    expect(postRoot).toBe(tree.getRoot());

    expect(await appClient.state.box.pendingLeaves.getMap()).toEqual(new Map());

    const spendGroup = await client.composeSpendGroup(
      spender.address,
      spender.spendKeypair,
      utxoInputs.secrets,
      tree.getMerkleProof(1),
      {
        amount: 1n,
        receiver: MithrasAccount.generate().address,
      },
    );

    // NOTE: There seems to be a bug with the signer for the lsig, for some reason the lsig txn is getting an ed25519 sig
    const innerComposer = await spendGroup.composer();
    const { atc } = await innerComposer.build();
    const txnsWithSigners = atc.buildGroup();
    txnsWithSigners[0]!.signer = (
      await client.spendVerifier.lsigAccount()
    ).signer;

    const composer = algorand.newGroup();
    composer.addAtc(atc);

    await composer.send();
  });
});
