import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import {
  MithrasClient,
  MithrasFactory,
} from "../../mithras-contracts-and-circuits/contracts/clients/Mithras";

import { beforeAll, describe, expect, it } from "vitest";
import { Address } from "algosdk";
import {
  depositVerifier,
  MithrasProtocolClient,
  spendVerifier,
} from "../../mithras-contracts-and-circuits/src";
import { TREE_DEPTH } from "../../mithras-contracts-and-circuits/src/constants";
import {
  DiscoveryKeypair,
  MithrasAddr,
  SpendSeed,
  SupportedHpkeSuite,
} from "../../mithras-crypto/src";
import { MithrasSubscriber } from "../src";

const SPEND_LSIGS = 12;
const LSIGS_FEE = BigInt(SPEND_LSIGS) * 1000n;
const SPEND_APP_FEE = 110n * 1000n;
const DEPOSIT_APP_FEE = 53n * 1000n;
const APP_MBR = 1567900n;
const BOOTSTRAP_FEE = 51n * 1000n;
const NULLIFIER_MBR = 15_700n;

const BLS12_381_SCALAR_MODULUS = BigInt(
  "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
);

function addressInScalarField(addr: Address): bigint {
  const asBigint = BigInt("0x" + Buffer.from(addr.publicKey).toString("hex"));
  return asBigint % BLS12_381_SCALAR_MODULUS;
}

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
  });
});
