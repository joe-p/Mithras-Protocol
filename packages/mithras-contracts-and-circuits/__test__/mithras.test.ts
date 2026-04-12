import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import { MithrasClient } from "../contracts/clients/Mithras";

import { beforeEach, describe, expect, it } from "vitest";
import { Address } from "algosdk";
import { MithrasProtocolClient } from "../src";
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
  let depositor: Address;

  beforeEach(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    depositor = await algorand.account.localNetDispenser();

    algorand.setSuggestedParamsCacheTimeout(0);

    const deployment = await MithrasProtocolClient.deploy(algorand, depositor);
    appClient = algorand.client.getTypedAppClientById(MithrasClient, {
      appId: deployment.appClient.appId,
      defaultSender: depositor,
    });
  });

  it("deposit", async () => {
    const client = new MithrasProtocolClient(algorand, appClient.appId);
    const tree = new MimcMerkleTree();

    const preRoot = await appClient.state.global.lastComputedRoot();
    expect(preRoot).toBe(tree.getRoot());

    const { group, utxoInputs } = await client.composeDepositGroup(
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

    const postRoot = await appClient.state.global.lastComputedRoot();
    expect(postRoot).not.toBe(preRoot);
    tree.addLeaf(utxoInputs.secrets.computeCommitment());
    expect(postRoot).toBe(tree.getRoot());
  });

  it("spend", async () => {
    const client = new MithrasProtocolClient(algorand, appClient.appId);
    const tree = new MimcMerkleTree();

    const spender = MithrasAccount.generate();
    const preRoot = await appClient.state.global.lastComputedRoot();
    expect(preRoot).toBe(tree.getRoot());

    const { group, utxoInputs } = await client.composeDepositGroup(
      depositor,
      1_000_000n,
      spender.address,
    );

    await group.send();

    const postRoot = await appClient.state.global.lastComputedRoot();
    expect(postRoot).not.toBe(preRoot);
    tree.addLeaf(utxoInputs.secrets.computeCommitment());
    expect(postRoot).toBe(tree.getRoot());

    const {
      group: spendGroup,
      out0Inputs,
      out1Inputs,
    } = await client.composeSpendGroup(
      spender.address,
      spender.spendKeypair,
      utxoInputs.secrets,
      tree.getMerkleProof(0),
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

    const nullifier = utxoInputs.secrets.computeNullifier();
    const nullifiers = await appClient.state.box.nullifiers.getMap();
    expect(nullifiers.has(nullifier)).toBe(true);

    const postSpendRoot = await appClient.state.global.lastComputedRoot();
    tree.addLeaf(out0Inputs.secrets.computeCommitment());
    tree.addLeaf(out1Inputs.secrets.computeCommitment());
    expect(postSpendRoot).toBe(tree.getRoot());
  });
});
