import { AlgorandClient } from "@algorandfoundation/algokit-utils/types/algorand-client";
import { microAlgos } from "@algorandfoundation/algokit-utils";
import {
  MimcMerkleContractFactory,
  MimcMerkleContractClient,
} from "../../contracts/clients/MimcMerkleContract";
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

export class MimcMerkleContractHelper {
  static async deployContract(): Promise<MimcMerkleContractClient> {
    const algorand = AlgorandTestUtils.createLocalClient();
    const factory = new MimcMerkleContractFactory({
      algorand,
      defaultSender: await AlgorandTestUtils.getDispenser(algorand),
    });

    const { appClient } = await factory.deploy({
      appName: AlgorandTestUtils.generateRandomAppName("mimc-merkle"),
    });

    await AlgorandTestUtils.fundAccount(
      algorand,
      appClient.appAddress,
      1567900,
    );

    await appClient.send.bootstrap({
      args: {},
      extraFee: microAlgos(256 * 1000),
    });

    return appClient;
  }

  static async addLeaf(
    appClient: MimcMerkleContractClient,
    leafHash: Uint8Array,
  ): Promise<void> {
    await appClient.send.addLeaf({
      args: { leafHash },
      extraFee: microAlgos(256 * 1000),
    });
  }

  static async getContractState(appClient: MimcMerkleContractClient) {
    const subtree = await appClient.state.box.subtree();
    const zeroHashes = await appClient.state.box.zeroHashes();

    if (!subtree || !zeroHashes) {
      throw new Error("Failed to get state from contract");
    }

    return { subtree, zeroHashes };
  }

  static async verifyRoot(
    appClient: MimcMerkleContractClient,
    root: Uint8Array,
  ): Promise<boolean> {
    const { return: isValid } = await appClient.send.isValidRoot({
      args: { root },
    });
    return isValid!;
  }
}

