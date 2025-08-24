import {
  assertMatch,
  gtxn,
  uint64,
  assert,
  abimethod,
  GlobalState,
  contract,
  bytes,
  ensureBudget,
  op,
} from "@algorandfoundation/algorand-typescript";
import { MimcMerkle } from "./mimc_merkle.algo";
import { methodSelector } from "@algorandfoundation/algorand-typescript/arc4";

const VERIFY_SIG =
  "verify(uint256[],(byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],uint256,uint256,uint256,uint256,uint256,uint256))void";

function getSignal(signals: bytes, idx: uint64): bytes<32> {
  const start: uint64 = idx * 32;
  return op.extract(signals, 2 + start, 32).toFixed({ length: 32 });
}

@contract({ avmVersion: 11 })
export class Mithras extends MimcMerkle {
  depositVerifierId = GlobalState<uint64>({ key: "d" });
  spendVerifierId = GlobalState<uint64>({ key: "s" });

  createApplication(depositVerifierId: uint64, spendVerifierId: uint64) {
    this.depositVerifierId.value = depositVerifierId;
    this.spendVerifierId.value = spendVerifierId;
  }

  bootstrapMerkleTree() {
    this.bootstrap();
  }

  //
  // "name": "verify",
  //    "args": [
  //        {
  //            "type": "uint256[]",
  //            "name": "signals"
  //        },
  //        {
  //            "type": "(byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],uint256,uint256,uint256,uint256,uint256,uint256)",
  //            "struct": "Proof",
  //            "name": "proof"
  //        }
  //    ],
  //    "returns": {
  //        "type": "void"
  //    },
  deposit(verifierCall: gtxn.ApplicationCallTxn) {
    assert(verifierCall.appId.id === this.depositVerifierId.value);
    assert(verifierCall.appArgs(0) === methodSelector(VERIFY_SIG));

    const signals = verifierCall.appArgs(1);
    const commitment = getSignal(signals, 0);
    this.addLeaf(commitment);
  }

  // // Public inputs
  //  signal input fee;
  //  signal input utxo_spender; // P' (receiver of UTXO)
  //
  //  // Public outputs
  //  signal output out0_commitment;
  //  signal output out1_commitment;
  //  signal output utxo_root;
  //  signal output utxo_nullifier;
  spend(verifierCall: gtxn.ApplicationCallTxn) {
    assert(verifierCall.appId.id === this.spendVerifierId.value);
    assert(verifierCall.appArgs(0) === methodSelector(VERIFY_SIG));

    const signals = verifierCall.appArgs(1);
    const out0Commitment = getSignal(signals, 2);
    const out1Commitment = getSignal(signals, 3);
    const utxoRoot = getSignal(signals, 4);
    assert(this.isValidRoot(utxoRoot), "Invalid UTXO root");

    this.addLeaf(out0Commitment);
    this.addLeaf(out1Commitment);
  }

  ensureBudget(budget: uint64) {
    ensureBudget(budget);
  }
}
