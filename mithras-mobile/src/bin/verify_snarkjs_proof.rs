use circom_prover::{prover::circom as cp, prover::CircomProof, prover::ProofLib, CircomProver};
use num_bigint::BigUint;
use serde_json::Value;
use std::env;
use std::fs;
use std::str::FromStr;

fn parse_biguint_str(v: &Value) -> BigUint {
    match v {
        Value::String(s) => BigUint::from_str(s).expect("invalid big integer string"),
        Value::Number(n) => BigUint::from_str(&n.to_string()).expect("invalid big integer number"),
        _ => panic!("expected string/number, got {v}"),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: verify_snarkjs_proof <zkey_path> <proof.json> <public.json>");
        std::process::exit(2);
    }

    let zkey_path = args[1].clone();
    let proof_path = args[2].clone();
    let public_path = args[3].clone();

    let proof_val: Value = serde_json::from_str(&fs::read_to_string(&proof_path).unwrap()).unwrap();
    let public_val: Value =
        serde_json::from_str(&fs::read_to_string(&public_path).unwrap()).unwrap();

    let pi_a = proof_val
        .get("pi_a")
        .expect("missing pi_a")
        .as_array()
        .unwrap();
    let pi_b = proof_val
        .get("pi_b")
        .expect("missing pi_b")
        .as_array()
        .unwrap();
    let pi_c = proof_val
        .get("pi_c")
        .expect("missing pi_c")
        .as_array()
        .unwrap();

    let b0 = pi_b[0].as_array().unwrap();
    let b1 = pi_b[1].as_array().unwrap();
    let b2 = pi_b[2].as_array().unwrap();

    let proof = cp::Proof {
        a: cp::G1 {
            x: parse_biguint_str(&pi_a[0]),
            y: parse_biguint_str(&pi_a[1]),
            z: parse_biguint_str(&pi_a[2]),
        },
        b: cp::G2 {
            x: [parse_biguint_str(&b0[0]), parse_biguint_str(&b0[1])],
            y: [parse_biguint_str(&b1[0]), parse_biguint_str(&b1[1])],
            z: [parse_biguint_str(&b2[0]), parse_biguint_str(&b2[1])],
        },
        c: cp::G1 {
            x: parse_biguint_str(&pi_c[0]),
            y: parse_biguint_str(&pi_c[1]),
            z: parse_biguint_str(&pi_c[2]),
        },
        protocol: proof_val
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("groth16")
            .to_string(),
        curve: proof_val
            .get("curve")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    };

    let pub_inputs: Vec<String> = public_val
        .as_array()
        .expect("public.json must be an array")
        .iter()
        .map(|v| match v {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => panic!("public signal must be string/number"),
        })
        .collect();

    let cp = CircomProof {
        proof,
        pub_inputs: pub_inputs.into(),
    };

    let ok = CircomProver::verify(ProofLib::Arkworks, cp, zkey_path).unwrap();
    println!("verified: {ok}");
}
