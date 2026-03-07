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
  biguint,
  BoxMap,
  itxn,
  emit,
  TransactionType,
  Account,
} from "@algorandfoundation/algorand-typescript";
import { MimcMerkle, PlonkProof } from "./mimc_merkle.algo";
import { Address, Uint256 } from "@algorandfoundation/algorand-typescript/arc4";

const BLS12_381_SCALAR_MODULUS = BigUint(
  "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
);

const HPKE_SIZE = 250;

/**
 * Event emitted when a new leaf is added to the tree. Global state deltas will contain the new index and root
 */
type NewLeaf = {
  leaf: Uint256;
  epochId: uint64;
};

type PendingLeaf = {
  leaf: Uint256;
};

@contract({ avmVersion: 11 })
export class Mithras extends MimcMerkle {
  depositVerifier = GlobalState<Address>({ key: "d" });
  spendVerifier = GlobalState<Address>({ key: "s" });
  creationRound = GlobalState<uint64>({ key: "cr" });

  nullifiers = BoxMap<Uint256, bytes<0>>({ keyPrefix: "n" });

  createApplication(depositVerifier: Address, spendVerifier: Address) {
    this.depositVerifier.value = depositVerifier;
    this.spendVerifier.value = spendVerifier;
    this.creationRound.value = Global.round;
  }

  bootstrapMerkleTree(commitLeafVerifier: Account) {
    this.bootstrap(commitLeafVerifier);
  }

  private addPendingUtxo(commitment: Uint256) {
    this.addPendingLeaf(commitment);
    emit<PendingLeaf>({
      leaf: commitment,
    });
  }

  commitUtxo(
    verifier: gtxn.Transaction,
    signals: Uint256[],
    proof: PlonkProof,
  ) {
    this.commitLeaf(verifier, signals, proof);
  }

  deposit(
    signals: Uint256[],
    _proof: PlonkProof,
    _outHpke: bytes<typeof HPKE_SIZE>,
    deposit: gtxn.PaymentTxn,
    verifierTxn: gtxn.Transaction,
  ) {
    assert(verifierTxn.sender === this.depositVerifier.value.native);

    const commitment = signals[0];
    const amount = op.extractUint64(signals[1].bytes, 24);

    this.addPendingUtxo(commitment);

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

    const out0Commitment = signals[0];
    const out1Commitment = signals[1];
    const utxoRoot = signals[2];
    const nullifier = signals[3];
    const utxoFee = op.extractUint64(signals[4].bytes, 24);
    const spender = signals[5];

    assert(!this.nullifiers(nullifier).exists, "Nullifier already exists");

    const preMBR = Global.currentApplicationAddress.minBalance;
    this.nullifiers(nullifier).create();
    const postMBR = Global.currentApplicationAddress.minBalance;

    const nullifierMbr: uint64 = postMBR - preMBR;

    assert(
      utxoFee >= nullifierMbr,
      "Fee does not cover nullifier storage cost",
    );

    const senderInScalarField: biguint =
      BigUint(Txn.sender.bytes) % BLS12_381_SCALAR_MODULUS;

    assert(BigUint(spender.bytes) === senderInScalarField, "Invalid spender");

    assert(this.isValidRoot(utxoRoot), "Invalid UTXO root");

    this.addPendingUtxo(out0Commitment);
    this.addPendingUtxo(out1Commitment);

    this.maybeCoverFee(utxoFee - nullifierMbr);
  }

  private maybeCoverFee(coverageAmount: uint64) {
    // Don't do anything if...
    if (
      coverageAmount === 0 ||
      // There are no more txns in the group
      Global.groupSize <= Txn.groupIndex + 1 ||
      // The next txn isn't a payment
      gtxn.Transaction(Txn.groupIndex + 1).type !== TransactionType.Payment
    ) {
      return;
    }

    const feePayment = gtxn.PaymentTxn(Txn.groupIndex + 1);

    // Only cover the fee if the next txn is 0 ALGO pay that closes back to the app
    if (
      // We probably don't care who the sender is, but check here just to be safe
      feePayment.sender === Txn.sender &&
      // Checking the receiver is probably superfluous since we later check close, but might as well be safe
      feePayment.receiver === Global.currentApplicationAddress &&
      // Ensure the amount is zero so we can be sure the account is spending Mithras ALGO on anything else
      feePayment.amount === 0 &&
      // Always close to the app to ensure it gets back any excess from the sender
      // This is especially important since we always send Global.minBalance
      // This is also important for the future when fees may be refundable
      feePayment.closeRemainderTo === Global.currentApplicationAddress
      // NOTE: We don't do any fee amount checks here since the fees may be partially covered by
      // some other txn in the group
    ) {
      itxn
        .payment({
          receiver: Txn.sender,
          // We always add Global.minBalance assuming the account has 0 ALGO
          amount: Global.minBalance + coverageAmount,
        })
        .submit();
    }
  }

  ensureBudget(budget: uint64) {
    ensureBudget(budget);
  }
}
