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

function getSignal(signals: bytes, idx: uint64): bytes<32> {
  const start: uint64 = idx * 32;
  return op.extract(signals, 2 + start, 32).toFixed({ length: 32 });
}

@contract({ avmVersion: 11 })
class Mithras extends MimcMerkle {
  verifierAppId = GlobalState<uint64>({ key: "v" });

  createApplication(verifierAppId: uint64) {
    this.verifierAppId.value = verifierAppId;
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
    assert(verifierCall.appId.id === this.verifierAppId.value);
    assert(
      verifierCall.appArgs(0) ===
        methodSelector(
          "verify(uint256[],(byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],uint256,uint256,uint256,uint256,uint256,uint256))void",
        ),
    );

    const signals = verifierCall.appArgs(1);
    const commitment = getSignal(signals, 0);
    this.addLeaf(commitment);
  }

  ensureBudget() {
    ensureBudget(132283);
  }
}
