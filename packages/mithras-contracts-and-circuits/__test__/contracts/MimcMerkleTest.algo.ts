import {
  contract,
  uint64,
  Account,
  gtxn,
} from "@algorandfoundation/algorand-typescript";
import {
  CommitLeafArgs,
  MimcMerkle,
} from "../../contracts/mimc_merkle/mimc_merkle.algo";
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";

@contract({ avmVersion: 11 })
export class MimcMerkleTest extends MimcMerkle {
  bootstrapTest(lsig: Account) {
    this.bootstrap(lsig);
  }

  addLeafTest(leafHash: Uint256, incentive: uint64) {
    this.addPendingLeaf(leafHash, incentive);
  }

  commitLeafTest(lsigTxn: gtxn.Transaction, args: CommitLeafArgs) {
    this.commitLeafWithLsig(lsigTxn, args);
  }

  isValidRootTest(root: Uint256) {
    return this.isValidRoot(root);
  }
}
