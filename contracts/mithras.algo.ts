import {
  gtxn,
  uint64,
  assert,
  GlobalState,
  contract,
  bytes,
  ensureBudget,
  op,
} from "@algorandfoundation/algorand-typescript";
import { MimcMerkle } from "./mimc_merkle.algo";
import { Address } from "@algorandfoundation/algorand-typescript/arc4";

function getSignal(signals: bytes, idx: uint64): bytes<32> {
  const start: uint64 = idx * 32;
  return op.extract(signals, 2 + start, 32).toFixed({ length: 32 });
}

@contract({ avmVersion: 11 })
export class Mithras extends MimcMerkle {
  depositVerifier = GlobalState<Address>({ key: "d" });
  spendVerifier = GlobalState<Address>({ key: "s" });

  createApplication(depositVerifier: Address, spendVerifier: Address) {
    this.depositVerifier.value = depositVerifier;
    this.spendVerifier.value = spendVerifier;
  }

  bootstrapMerkleTree() {
    this.bootstrap();
  }

  deposit(signalsAndProofCall: gtxn.ApplicationCallTxn) {
    assert(signalsAndProofCall.sender === this.depositVerifier.value.native);

    const signals = signalsAndProofCall.appArgs(1);
    const commitment = getSignal(signals, 0);
    this.addLeaf(commitment);
  }

  spend(verifierCall: gtxn.ApplicationCallTxn) {
    assert(verifierCall.sender === this.spendVerifier.value.native);

    const signals = verifierCall.appArgs(1);
    // const fee = getSignal(signals, 0);
    // const utxoSpender = getSignal(signals, 1);
    const out0Commitment = getSignal(signals, 2);
    const out1Commitment = getSignal(signals, 3);
    const utxoRoot = getSignal(signals, 4);
    // const utxoNullifier = getSignal(signals, 5);
    assert(this.isValidRoot(utxoRoot), "Invalid UTXO root");

    this.addLeaf(out0Commitment);
    this.addLeaf(out1Commitment);
  }

  ensureBudget(budget: uint64) {
    ensureBudget(budget);
  }
}
