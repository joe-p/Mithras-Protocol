import {
  assert,
  Box,
  bytes,
  clone,
  Contract,
  FixedArray,
  GlobalState,
  op,
  uint64,
  contract,
  ensureBudget,
} from "@algorandfoundation/algorand-typescript";

const ROOT_CACHE_SIZE = 50;
const TREE_HEIGHT = 32;

@contract({ avmVersion: 11 })
export class MimcMerkle extends Contract {
  rootCache = Box<FixedArray<bytes<32>, typeof ROOT_CACHE_SIZE>>({ key: "r" });

  rootCounter = GlobalState<uint64>({ key: "c" });

  subtree = Box<FixedArray<bytes<32>, typeof TREE_HEIGHT>>({ key: "t" });

  treeIndex = GlobalState<uint64>({ key: "i" });

  zeroHashes = Box<FixedArray<bytes<32>, typeof TREE_HEIGHT>>({ key: "z" });

  bootstrap(): void {
    ensureBudget(700 * 200);
    const tree = new FixedArray<bytes<32>, typeof TREE_HEIGHT>();

    tree[0] = op.bzero(32).toFixed({ length: 32 });

    for (let i: uint64 = 1; i < TREE_HEIGHT; i++) {
      tree[i] = op.mimc(
        op.MimcConfigurations.BLS12_381Mp111,
        tree[i - 1].concat(tree[i - 1]),
      );
    }

    this.rootCounter.value = 0;
    this.treeIndex.value = 0;
    this.rootCache.create();
    this.zeroHashes.value = clone(tree);
    this.subtree.value = clone(tree);
  }

  addLeaf(leafHash: bytes<32>): void {
    ensureBudget(700 * 200);

    let index = this.treeIndex.value;

    assert(index < 2 ** TREE_HEIGHT, "Tree is full");

    this.treeIndex.value += 1;
    let currentHash = leafHash;
    let left: bytes<32>;
    let right: bytes<32>;
    let subtree = clone(this.subtree.value);
    const zeroHashes = clone(this.zeroHashes.value);

    for (let i: uint64 = 0; i < TREE_HEIGHT; i++) {
      if ((index & 1) === 0) {
        subtree[i] = currentHash;
        left = currentHash;
        right = zeroHashes[i];
      } else {
        left = subtree[i];
        right = currentHash;
      }

      currentHash = op.mimc(
        op.MimcConfigurations.BLS12_381Mp111,
        left.concat(right),
      );

      index >>= 1;
    }

    this.subtree.value = clone(subtree);
    this.addRoot(currentHash);
  }

  isValidRoot(root: bytes<32>): boolean {
    for (const validRoot of this.rootCache.value) {
      if (root === validRoot) {
        return true;
      }
    }

    return false;
  }

  addRoot(rootHash: bytes<32>): void {
    const index: uint64 = this.rootCounter.value % ROOT_CACHE_SIZE;
    this.rootCache.value[index] = rootHash;

    this.rootCounter.value += 1;
  }
}
