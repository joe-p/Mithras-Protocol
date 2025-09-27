import { microAlgos } from "@algorandfoundation/algokit-utils";
import {
  MimcMerkleTestFactory,
  MimcMerkleTestClient,
} from "../contracts/clients/MimcMerkleTest";
import { MimcTestClient, MimcTestFactory } from "../contracts/clients/MimcTest";
import { AlgorandTestUtils } from "./test-utils";

export class MimcTestHelper {
  static async deployContract(): Promise<MimcTestClient> {
    const algorand = AlgorandTestUtils.createLocalClient();
    const factory = new MimcTestFactory({
      algorand,
      defaultSender: await AlgorandTestUtils.getDispenser(algorand),
    });

    const { appClient } = await factory.deploy({
      appName: AlgorandTestUtils.generateRandomAppName("mimc-test"),
    });

    return appClient;
  }
}

export class MimcMerkleHelper {
  static async deployContract(): Promise<MimcMerkleTestClient> {
    const algorand = AlgorandTestUtils.createLocalClient();
    const factory = new MimcMerkleTestFactory({
      algorand,
      defaultSender: await AlgorandTestUtils.getDispenser(algorand),
    });

    const { appClient } = await factory.deploy({
      appName: AlgorandTestUtils.generateRandomAppName("mimc-merkle"),
    });

    await AlgorandTestUtils.fundAccount(
      algorand,
      appClient.appAddress,
      4848000,
    );

    await appClient.send.bootstrapTest({
      args: {},
      extraFee: microAlgos(256 * 1000),
    });

    return appClient;
  }

  static async addLeaf(
    appClient: MimcMerkleTestClient,
    leafHash: Uint8Array,
  ): Promise<void> {
    await appClient.send.addLeafTest({
      args: { leafHash },
      extraFee: microAlgos(256 * 1000),
    });
  }

  static async sealAndRotate(appClient: MimcMerkleTestClient): Promise<void> {
    await appClient.send.sealAndRotateTest({
      args: {},
      extraFee: microAlgos(256 * 1000),
    });
  }

  static async isValidSealedRoot(
    appClient: MimcMerkleTestClient,
    epochId: bigint,
    root: Uint8Array,
  ): Promise<boolean> {
    const result = await appClient.send.isValidSealedRootTest({
      args: { epochId, root },
    });

    return result.return!;
  }

  static async getContractState(appClient: MimcMerkleTestClient) {
    const subtree = await appClient.state.box.subtree();
    const zeroHashes = await appClient.state.box.zeroHashes();

    if (!subtree || !zeroHashes) {
      throw new Error("Failed to get state from contract");
    }

    return { subtree, zeroHashes };
  }

  static async verifyRoot(
    appClient: MimcMerkleTestClient,
    root: Uint8Array,
  ): Promise<boolean> {
    const { return: isValid } = await appClient.send.isValidRootTest({
      args: { root },
    });
    return isValid!;
  }
}
