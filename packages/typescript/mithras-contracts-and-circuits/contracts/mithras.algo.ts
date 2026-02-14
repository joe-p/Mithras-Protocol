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
} from "@algorandfoundation/algorand-typescript";
import { MimcMerkle } from "./mimc_merkle.algo";
import { Address } from "@algorandfoundation/algorand-typescript/arc4";

const BLS12_381_SCALAR_MODULUS = BigUint(
  Bytes.fromHex(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
  ),
);

function getSignal(signals: bytes, idx: uint64): bytes<32> {
  const start: uint64 = idx * 32;
  return op.extract(signals, 2 + start, 32).toFixed({ length: 32 });
}

const HPKE_SIZE = 250;

@contract({ avmVersion: 11 })
export class Mithras extends MimcMerkle {
  depositVerifier = GlobalState<Address>({ key: "d" });
  spendVerifier = GlobalState<Address>({ key: "s" });

  nullifiers = BoxMap<bytes<32>, bytes<0>>({ keyPrefix: "n" });

  createApplication(depositVerifier: Address, spendVerifier: Address) {
    this.depositVerifier.value = depositVerifier;
    this.spendVerifier.value = spendVerifier;
  }

  bootstrapMerkleTree() {
    this.bootstrap();
  }

  deposit(
    signalsAndProofCall: gtxn.ApplicationCallTxn,
    deposit: gtxn.PaymentTxn,
    _outHpke: bytes<typeof HPKE_SIZE>,
  ) {
    assert(signalsAndProofCall.sender === this.depositVerifier.value.native);

    const signals = signalsAndProofCall.appArgs(1);

    const commitment = getSignal(signals, 0);
    const amount = op.extractUint64(getSignal(signals, 1), 24);

    this.addLeaf(commitment);

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
    verifierCall: gtxn.ApplicationCallTxn,
    _out0Hpke: bytes<typeof HPKE_SIZE>,
    _out1Hpke: bytes<typeof HPKE_SIZE>,
  ) {
    assert(
      verifierCall.sender === this.spendVerifier.value.native,
      "sender of verifier call must be the spend verifier lsig",
    );

    const signals = verifierCall.appArgs(1);

    const out0Commitment = getSignal(signals, 0);
    const out1Commitment = getSignal(signals, 1);
    const utxoRoot = getSignal(signals, 2);
    const nullifier = getSignal(signals, 3);
    const fee = op.extractUint64(getSignal(signals, 4), 24);
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

    assert(BigUint(spender) === senderInScalarField, "Invalid spender");

    assert(this.isValidRoot(utxoRoot), "Invalid UTXO root");

    this.addLeaf(out0Commitment);
    this.addLeaf(out1Commitment);
  }

  ensureBudget(budget: uint64) {
    ensureBudget(budget);
  }
}
