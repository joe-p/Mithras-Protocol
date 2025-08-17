import {
  BigUint,
  Bytes,
  bytes,
  Contract,
  contract,
  op,
} from "@algorandfoundation/algorand-typescript";
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";

type Output = {
  out: Uint256;
};

@contract({ avmVersion: 11 })
export class MimcTest extends Contract {
  mimcTest(msg: Uint256): Output {
    const hash = op.mimc(op.MimcConfigurations.BLS12_381Mp111, msg.bytes);
    return {
      out: new Uint256(BigUint(hash)),
    };
  }
}
