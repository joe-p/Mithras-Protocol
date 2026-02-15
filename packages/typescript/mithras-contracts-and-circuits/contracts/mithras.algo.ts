import {
  gtxn,
  uint64,
  assert,
  GlobalState,
  contract,
  bytes,
  ensureBudget,
  op,
  Global,
  assertMatch,
  BigUint,
  Txn,
  Bytes,
  biguint,
  BoxMap,
  itxn,
  FixedArray,
  Application,
  clone,
} from "@algorandfoundation/algorand-typescript";
import { MimcMerkle } from "./mimc_merkle.algo";
import {
  Address,
  compileArc4,
  Contract,
  Uint256,
} from "@algorandfoundation/algorand-typescript/arc4";
import { TREE_DEPTH } from "../src/constants";

const BLS12_381_SCALAR_MODULUS = BigUint(
  Bytes.fromHex(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
  ),
);

function getSignal(signals: Uint256[], idx: uint64): Uint256 {
  return signals[idx];
}

const HPKE_SIZE = 250;

/**
 * PLONK proof structure: G1 points (96B BE) and field evals (32B BE)
 */
export type PlonkProof = {
  // Uncompressed G1 points
  A: bytes<96>;
  B: bytes<96>;
  C: bytes<96>;
  Z: bytes<96>;
  T1: bytes<96>;
  T2: bytes<96>;
  T3: bytes<96>;
  Wxi: bytes<96>;
  Wxiw: bytes<96>;
  // Field evaluations are 32 bytes (SNARKJS internal representation, BE)
  eval_a: Uint256;
  eval_b: Uint256;
  eval_c: Uint256;
  eval_s1: Uint256;
  eval_s2: Uint256;
  eval_zw: Uint256;
};

type NewLeaf = {
  leaf: Uint256;
  subtree: FixedArray<Uint256, typeof TREE_DEPTH>;
  epochId: uint64;
  treeIndex: uint64;
};

/**
 * The AVM has a 1k log limit. Each NewLeaf log is about 800 bytes, so we can only log one per app call.
 * To work around this, we have a separate contract that we call from the outer contract and use the args
 * as a way to log the events. This breaks compatibility with ARC28, but that is an acceptable tradeoff
 * as parsing the args from the inner transactions will be fairly straightforward
 */
export class MithrasLogger extends Contract {
  newLeaf(_newLeaf: NewLeaf) {}
  newLeaf2(_newLeaf: NewLeaf, _newLeaf2: NewLeaf) {}
}

@contract({ avmVersion: 11 })
export class Mithras extends MimcMerkle {
  depositVerifier = GlobalState<Address>({ key: "d" });
  spendVerifier = GlobalState<Address>({ key: "s" });
  logger = GlobalState<Application>({ key: "l" });

  nullifiers = BoxMap<Uint256, bytes<0>>({ keyPrefix: "n" });

  createApplication(depositVerifier: Address, spendVerifier: Address) {
    this.depositVerifier.value = depositVerifier;
    this.spendVerifier.value = spendVerifier;
  }

  bootstrapMerkleTree() {
    const loggerClient = compileArc4(MithrasLogger, {});
    this.bootstrap();
    const res = loggerClient.bareCreate();
    this.logger.value = res.createdApp;
  }

  deposit(
    signals: Uint256[],
    _proof: PlonkProof,
    _outHpke: bytes<typeof HPKE_SIZE>,
    deposit: gtxn.PaymentTxn,
    verifierTxn: gtxn.Transaction,
  ) {
    assert(verifierTxn.sender === this.depositVerifier.value.native);

    const commitment = getSignal(signals, 0);
    const amount = op.extractUint64(getSignal(signals, 1).bytes, 24);

    this.addLeaf(commitment);

    const loggerClient = compileArc4(MithrasLogger, {});

    const newLeaf: NewLeaf = {
      leaf: commitment,
      subtree: clone(this.subtree.value),
      epochId: this.epochId.value,
      treeIndex: this.treeIndex.value - 1,
    };

    loggerClient.call.newLeaf({
      appId: this.logger.value,
      args: [newLeaf],
    });

    assertMatch(
      deposit,
      {
        amount: amount,
        receiver: Global.currentApplicationAddress,
      },
      "invalid deposit txn",
    );
  }

  spend(
    signals: Uint256[],
    _proof: PlonkProof,
    _out0Hpke: bytes<typeof HPKE_SIZE>,
    _out1Hpke: bytes<typeof HPKE_SIZE>,
    verifierTxn: gtxn.Transaction,
  ) {
    assert(
      verifierTxn.sender === this.spendVerifier.value.native,
      "sender of verifier call must be the spend verifier lsig",
    );

    const out0Commitment = getSignal(signals, 0);
    const out1Commitment = getSignal(signals, 1);
    const utxoRoot = getSignal(signals, 2);
    const nullifier = getSignal(signals, 3);
    const fee = op.extractUint64(getSignal(signals, 4).bytes, 24);
    const spender = getSignal(signals, 5);

    assert(!this.nullifiers(nullifier).exists, "Nullifier already exists");

    const preMBR = Global.currentApplicationAddress.minBalance;
    this.nullifiers(nullifier).create();
    const postMBR = Global.currentApplicationAddress.minBalance;

    const nullifierMbr: uint64 = postMBR - preMBR;

    assert(fee >= nullifierMbr, "Fee does not cover nullifier storage cost");

    if (fee - nullifierMbr > 0) {
      itxn
        .payment({
          receiver: Txn.sender,
          amount: fee - nullifierMbr,
        })
        .submit();
    }

    const senderInScalarField: biguint =
      BigUint(Txn.sender.bytes) % BLS12_381_SCALAR_MODULUS;

    assert(spender.native === senderInScalarField, "Invalid spender");

    assert(this.isValidRoot(utxoRoot), "Invalid UTXO root");

    const loggerClient = compileArc4(MithrasLogger, {});

    this.addLeaf(out0Commitment);
    const newLeaf0: NewLeaf = {
      leaf: out0Commitment,
      subtree: clone(this.subtree.value),
      epochId: this.epochId.value,
      treeIndex: this.treeIndex.value - 1,
    };

    this.addLeaf(out1Commitment);
    const newLeaf1: NewLeaf = {
      leaf: out1Commitment,
      subtree: clone(this.subtree.value),
      epochId: this.epochId.value,
      treeIndex: this.treeIndex.value - 1,
    };

    loggerClient.call.newLeaf2({
      appId: this.logger.value,
      args: [newLeaf0, newLeaf1],
    });
  }

  ensureBudget(budget: uint64) {
    ensureBudget(budget);
  }
}
