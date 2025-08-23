import {
  bytes,
  contract,
  FixedArray,
  uint64,
} from "@algorandfoundation/algorand-typescript";
import { MimcMerkle } from "../../contracts/mimc_merkle.algo";

@contract({ avmVersion: 11 })
export class MimcMerkleTest extends MimcMerkle {
  bootstrapTest() {
    this.bootstrap();
  }

  addLeafTest(leafHash: bytes<32>) {
    this.addLeaf(leafHash);
  }

  sealAndRotateTest() {
    this.sealAndRotate();
  }

  isValidRootTest(root: bytes<32>) {
    return this.isValidRoot(root);
  }

  isValidSealedRootTest(epochId: uint64, root: bytes<32>) {
    return this.isValidSealedRoot(epochId, root);
  }

  addRootTest(rootHash: bytes<32>) {
    this.addRoot(rootHash);
  }
}
