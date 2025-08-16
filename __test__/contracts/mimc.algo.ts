import {
  bytes,
  Contract,
  contract,
  op,
} from "@algorandfoundation/algorand-typescript";
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";

@contract({ avmVersion: 11 })
export class MimcTest extends Contract {
  mimcTest(v: Uint256): bytes<32> {
    return op.mimc(op.MimcConfigurations.BLS12_381Mp111, v.bytes);
  }
}
