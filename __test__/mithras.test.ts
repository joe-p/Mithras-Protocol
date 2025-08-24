import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import { AppVerifier } from "snarkjs-algorand";
import { MithrasFactory } from "../contracts/clients/Mithras";

import { beforeAll, describe, it } from "vitest";

describe("Mithras App", () => {
  beforeAll(() => {});
  it("deposit", async () => {
    const algorand = AlgorandClient.defaultLocalNet();
    const verifier = new AppVerifier(
      algorand,
      "circuits/deposit_test.zkey",
      "circuits/deposit_js/deposit.wasm",
    );

    await verifier.deploy({
      defaultSender: await algorand.account.localNetDispenser(),
      onUpdate: "append",
    });

    const spending_secret = 111n;
    const nullifier_secret = 222n;
    const amount = 333n;
    const receiver = 444n;

    const verifierTxn = await verifier.verifyTransaction({
      spending_secret,
      nullifier_secret,
      amount,
      receiver,
    });

    const factory = new MithrasFactory({
      algorand,
      defaultSender: await algorand.account.localNetDispenser(),
    });

    const { appClient } = await factory.send.create.createApplication({
      args: [verifier.appClient!.appId],
    });

    // TODO: determine the actual MBR needed
    await appClient.appClient.fundAppAccount({ amount: microAlgos(4848000) });

    await appClient.send.bootstrapMerkleTree({
      args: {},
      // TODO: determine the actual fee needed
      extraFee: microAlgos(256 * 1000),
    });

    await appClient
      .newGroup()
      // TODO: call ensure budget in the snarkjs app
      .ensureBudget({ extraFee: microAlgos(256 * 1000), args: {} })
      .deposit({ args: [verifierTxn] })
      .send();
  });
});
