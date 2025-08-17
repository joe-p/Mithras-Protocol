import {
  BigUint,
  Contract,
  contract,
  FixedArray,
  op,
  ensureBudget,
} from "@algorandfoundation/algorand-typescript";
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";

type Output = {
  out: Uint256;
};

@contract({ avmVersion: 11 })
export class MimcTest extends Contract {
  mimcTest(msg: FixedArray<Uint256, 2>): Output {
    ensureBudget(1400);
    const hash = op.mimc(
      op.MimcConfigurations.BLS12_381Mp111,
      msg[0].bytes.concat(msg[1].bytes),
    );
    return {
      out: new Uint256(BigUint(hash)),
    };
  }
}
