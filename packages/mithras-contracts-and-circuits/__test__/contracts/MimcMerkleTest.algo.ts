import {
  bytes,
  contract,
  FixedArray,
  uint64,
} from "@algorandfoundation/algorand-typescript";
import { MimcMerkle } from "../../contracts/mimc_merkle.algo";
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";

@contract({ avmVersion: 11 })
export class MimcMerkleTest extends MimcMerkle {
  bootstrapTest() {
    this.bootstrap();
  }

  addLeafTest(leafHash: Uint256) {
    this.addLeaf(leafHash);
  }

  sealAndRotateTest() {
    this.sealAndRotate();
  }

  isValidRootTest(root: Uint256) {
    return this.isValidRoot(root);
  }

  isValidSealedRootTest(epochId: uint64, root: Uint256) {
    return this.isValidSealedRoot(epochId, root);
  }

  addRootTest(rootHash: Uint256) {
    this.addRoot(rootHash);
  }
}
