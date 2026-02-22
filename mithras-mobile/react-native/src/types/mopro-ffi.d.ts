declare module 'mopro-ffi' {
  export type G1Point = {
    x: string;
    y: string;
    z: string;
  };

  export type G2Point = {
    x: string[];
    y: string[];
    z: string[];
  };

  export type CircomProof = {
    a: G1Point;
    b: G2Point;
    c: G1Point;
    protocol: string;
    curve: string;
  };

  export type CircomProofResult = {
    proof: CircomProof;
    inputs: string[];
  };

  export enum ProofLib {
    Arkworks = 0,
  }

  export function generateCircomProof(
    zkeyPath: string,
    inputsJson: string,
    proofLib: ProofLib
  ): CircomProofResult;

  export function verifyCircomProof(
    zkeyPath: string,
    proof: CircomProofResult,
    proofLib: ProofLib
  ): boolean;
}
