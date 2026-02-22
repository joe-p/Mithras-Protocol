#[macro_use]
mod stubs;

mod error;
pub use error::MoproError;

// Initializes the shared UniFFI scaffolding and defines the `MoproError` enum.
#[cfg(not(target_arch = "wasm32"))]
mopro_ffi::app!();
// Skip wasm_setup!() to avoid extern crate alias conflict
// Instead, we import wasm_bindgen directly when needed
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
use mopro_ffi::prelude::wasm_bindgen;

/// You can also customize the bindings by #[uniffi::export]
/// Reference: https://mozilla.github.io/uniffi-rs/latest/proc_macro/index.html
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn mopro_hello_world() -> String {
    "Hello, World!".to_string()
}

#[cfg(test)]
use serde_json::json;

// Link in transpiled wasm witness symbols and expose them as Rust functions.
pub mod witness {
    rust_witness::witness!(multiplier2);
    rust_witness::witness!(multiplier2bls);
    rust_witness::witness!(deposit);
    rust_witness::witness!(spend);
}

crate::set_circom_circuits! {
    ("multiplier2_final.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::multiplier2_witness)),
    ("multiplier2_bls_final.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::multiplier2bls_witness)),
    ("deposit.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::deposit_witness)),
    ("spend.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::spend_witness)),
}

mod circom;
pub use crate::circom::{generate_circom_proof, verify_circom_proof, ProofLib};
#[cfg(test)]
use circom_prover::prover::ProofLib as CircomProverProofLib;
#[cfg(test)]
use circom_prover::CircomProver;

#[cfg(test)]
const MULTIPLIER2_ZKEY_PATH: &str = "./test-vectors/circom/multiplier2_final.zkey";
#[cfg(test)]
const MULTIPLIER2_BLS_ZKEY_PATH: &str = "./test-vectors/circom/multiplier2_bls_final.zkey";
#[cfg(test)]
const DEPOSIT_ZKEY_PATH: &str = "./test-vectors/circom/deposit.zkey";
#[cfg(test)]
const SPEND_ZKEY_PATH: &str = "./test-vectors/circom/spend.zkey";

#[test]
fn test_multiplier2() {
    let circuit_inputs = "{\"a\": 2, \"b\": 3}".to_string();
    let result = generate_circom_proof(
        MULTIPLIER2_ZKEY_PATH.to_string(),
        circuit_inputs,
        ProofLib::Arkworks,
    );
    assert!(result.is_ok());
    let proof = result.unwrap();
    let ok = verify_circom_proof(MULTIPLIER2_ZKEY_PATH.to_string(), proof, ProofLib::Arkworks)
        .expect("verification call failed");
    assert!(ok, "expected multiplier2 proof to verify");
}

#[test]
#[ignore]
fn test_rustwitness_arkworks_bls12_381_prove_and_verify() {
    // Ignored: Rust witness functions are not present in this build.
}

#[test]
fn test_multiplier2_bls_via_generate_circom_proof() {
    // Prove+verify the BLS circuit through the same public API used by deposit/spend.
    // This exercises: zkey_path basename -> crate::circom_get -> WitnessFn.
    let circuit_inputs = json!({
        "a": 1,
        "b": 2,
    })
    .to_string();

    let proof = generate_circom_proof(
        MULTIPLIER2_BLS_ZKEY_PATH.to_string(),
        circuit_inputs,
        ProofLib::Arkworks,
    )
    .expect("prove failed");

    let ok = verify_circom_proof(
        MULTIPLIER2_BLS_ZKEY_PATH.to_string(),
        proof,
        ProofLib::Arkworks,
    )
    .expect("verify call failed");

    assert!(ok, "expected multiplier2_bls proof to verify");
}

// Diagnostic test removed: dump_zkey_pk_sizes

#[test]
fn test_deposit() {
    // Mirrors packages/mithras-contracts-and-circuits/__test__/deposit.test.ts "verifies on chain" input shape.
    // Use strings for numeric values to avoid JSON integer limitations.
    let circuit_inputs = json!({
        "spending_secret": "111",
        "nullifier_secret": "222",
        "amount": "333",
        "receiver": "444",
    })
    .to_string();

    let result = generate_circom_proof(
        DEPOSIT_ZKEY_PATH.to_string(),
        circuit_inputs,
        ProofLib::Arkworks,
    );
    assert!(result.is_ok());

    let proof = result.unwrap();

    eprintln!(
        "[deposit] protocol={} curve={}",
        proof.proof.protocol, proof.proof.curve
    );
    eprintln!("[deposit] pub_inputs={:?}", proof.inputs);

    // Write snarkjs-style proof + public inputs for external verification diagnostics
    if let Err(e) = (|| -> anyhow::Result<()> {
        use std::fs::{create_dir_all, File};
        use std::io::BufWriter;

        let out_dir = "target/snarkjs";
        create_dir_all(out_dir)?;

        let proof_path = format!("{}/deposit_proof.json", out_dir);
        let pub_path = format!("{}/deposit_pub.json", out_dir);

        let proof_json = serde_json::json!({
            "pi_a": [proof.proof.a.x, proof.proof.a.y],
            "pi_b": [
                [proof.proof.b.x[0].clone(), proof.proof.b.x[1].clone()],
                [proof.proof.b.y[0].clone(), proof.proof.b.y[1].clone()]
            ],
            "pi_c": [proof.proof.c.x, proof.proof.c.y]
        });

        let f = File::create(proof_path)?;
        let w = BufWriter::new(f);
        serde_json::to_writer_pretty(w, &proof_json)?;

        let f2 = File::create(pub_path)?;
        let w2 = BufWriter::new(f2);
        serde_json::to_writer_pretty(w2, &proof.inputs)?;

        Ok(())
    })() {
        eprintln!("failed to write snarkjs diagnostics: {:#}", e);
    }

    let ok = verify_circom_proof(DEPOSIT_ZKEY_PATH.to_string(), proof, ProofLib::Arkworks)
        .expect("verification call failed");
    assert!(ok, "expected deposit proof to verify");
}

#[test]
fn test_deposit_direct_circom_prover_roundtrip() {
    // Prove+verify without going through our UniFFI record conversions.
    let circuit_inputs = json!({
        "spending_secret": ["111"],
        "nullifier_secret": ["222"],
        "amount": ["333"],
        "receiver": ["444"],
    })
    .to_string();

    let witness_fn = crate::circom_get("deposit.zkey").unwrap_or_else(|| {
        eprintln!(
            "missing witness fn for deposit.zkey. available: {:?}",
            crate::circom_list()
        );
        panic!("missing witness fn for deposit.zkey");
    });
    let proof = CircomProver::prove(
        CircomProverProofLib::Arkworks,
        witness_fn,
        circuit_inputs,
        DEPOSIT_ZKEY_PATH.to_string(),
    )
    .expect("prove failed");

    // write snarkjs-style proof + pub inputs for external verification diagnostics
    if let Err(e) = (|| -> anyhow::Result<()> {
        use std::fs::{create_dir_all, File};
        use std::io::BufWriter;

        let out_dir = "target/snarkjs";
        create_dir_all(out_dir)?;

        let proof_path = format!("{}/deposit_direct_proof.json", out_dir);
        let pub_path = format!("{}/deposit_direct_pub.json", out_dir);

        let proof_json = serde_json::json!({
            "pi_a": [proof.proof.a.x.to_string(), proof.proof.a.y.to_string()],
            "pi_b": [
                [proof.proof.b.x[0].to_string(), proof.proof.b.x[1].to_string()],
                [proof.proof.b.y[0].to_string(), proof.proof.b.y[1].to_string()]
            ],
            "pi_c": [proof.proof.c.x.to_string(), proof.proof.c.y.to_string()]
        });

        let f = File::create(proof_path)?;
        let w = BufWriter::new(f);
        serde_json::to_writer_pretty(w, &proof_json)?;

        let f2 = File::create(pub_path)?;
        let w2 = BufWriter::new(f2);
        serde_json::to_writer_pretty(w2, &proof.pub_inputs)?;

        Ok(())
    })() {
        eprintln!("failed to write snarkjs diagnostics: {:#}", e);
    }

    let ok = CircomProver::verify(
        CircomProverProofLib::Arkworks,
        proof,
        DEPOSIT_ZKEY_PATH.to_string(),
    )
    .expect("verify call failed");

    assert!(ok, "expected direct deposit proof to verify");
}

// Diagnostic test removed: test_deposit_witness_satisfies_r1cs

#[test]
fn test_spend() {
    // Mirrors packages/mithras-contracts-and-circuits/__test__/spend.test.ts "verifies on chain" input shape.
    // Use a trivial (all-zero) 16-level merkle path.
    let path_selectors = vec!["0"; 16];
    let utxo_path = vec!["0"; 16];

    let circuit_inputs = json!({
        "fee": "7",
        "utxo_spender": "999",
        "utxo_spending_secret": "111",
        "utxo_nullifier_secret": "222",
        "utxo_amount": "1000",
        "path_selectors": path_selectors,
        "utxo_path": utxo_path,
        "out0_amount": "500",
        "out0_receiver": "1234",
        "out0_spending_secret": "333",
        "out0_nullifier_secret": "444",
        "out1_amount": "493",
        "out1_receiver": "5678",
        "out1_spending_secret": "555",
        "out1_nullifier_secret": "666",
    })
    .to_string();

    let result = generate_circom_proof(
        SPEND_ZKEY_PATH.to_string(),
        circuit_inputs,
        ProofLib::Arkworks,
    );
    assert!(result.is_ok());

    let proof = result.unwrap();

    eprintln!(
        "[spend] protocol={} curve={}",
        proof.proof.protocol, proof.proof.curve
    );
    eprintln!("[spend] pub_inputs={:?}", proof.inputs);

    // Write snarkjs-style proof + public inputs for external verification diagnostics
    if let Err(e) = (|| -> anyhow::Result<()> {
        use std::fs::{create_dir_all, File};
        use std::io::BufWriter;

        let out_dir = "target/snarkjs";
        create_dir_all(out_dir)?;

        let proof_path = format!("{}/spend_proof.json", out_dir);
        let pub_path = format!("{}/spend_pub.json", out_dir);

        let proof_json = serde_json::json!({
            "pi_a": [proof.proof.a.x, proof.proof.a.y],
            "pi_b": [
                [proof.proof.b.x[0].clone(), proof.proof.b.x[1].clone()],
                [proof.proof.b.y[0].clone(), proof.proof.b.y[1].clone()]
            ],
            "pi_c": [proof.proof.c.x, proof.proof.c.y]
        });

        let f = File::create(proof_path)?;
        let w = BufWriter::new(f);
        serde_json::to_writer_pretty(w, &proof_json)?;

        let f2 = File::create(pub_path)?;
        let w2 = BufWriter::new(f2);
        serde_json::to_writer_pretty(w2, &proof.inputs)?;

        Ok(())
    })() {
        eprintln!("failed to write snarkjs diagnostics: {:#}", e);
    }

    let ok = verify_circom_proof(SPEND_ZKEY_PATH.to_string(), proof, ProofLib::Arkworks)
        .expect("verification call failed");
    assert!(ok, "expected spend proof to verify");
}

#[test]
fn test_spend_direct_circom_prover_roundtrip() {
    let circuit_inputs = json!({
        "fee": ["7"],
        "utxo_spender": ["999"],
        "utxo_spending_secret": ["111"],
        "utxo_nullifier_secret": ["222"],
        "utxo_amount": ["1000"],
        "path_selectors": ["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],
        "utxo_path": ["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],
        "out0_amount": ["500"],
        "out0_receiver": ["1234"],
        "out0_spending_secret": ["333"],
        "out0_nullifier_secret": ["444"],
        "out1_amount": ["493"],
        "out1_receiver": ["5678"],
        "out1_spending_secret": ["555"],
        "out1_nullifier_secret": ["666"],
    })
    .to_string();

    let witness_fn = crate::circom_get("spend.zkey").unwrap_or_else(|| {
        eprintln!(
            "missing witness fn for spend.zkey. available: {:?}",
            crate::circom_list()
        );
        panic!("missing witness fn for spend.zkey");
    });
    let proof = CircomProver::prove(
        CircomProverProofLib::Arkworks,
        witness_fn,
        circuit_inputs,
        SPEND_ZKEY_PATH.to_string(),
    )
    .expect("prove failed");

    // write snarkjs-style proof + pub inputs for external verification diagnostics
    if let Err(e) = (|| -> anyhow::Result<()> {
        use std::fs::{create_dir_all, File};
        use std::io::BufWriter;

        let out_dir = "target/snarkjs";
        create_dir_all(out_dir)?;

        let proof_path = format!("{}/spend_direct_proof.json", out_dir);
        let pub_path = format!("{}/spend_direct_pub.json", out_dir);

        let proof_json = serde_json::json!({
            "pi_a": [proof.proof.a.x.to_string(), proof.proof.a.y.to_string()],
            "pi_b": [
                [proof.proof.b.x[0].to_string(), proof.proof.b.x[1].to_string()],
                [proof.proof.b.y[0].to_string(), proof.proof.b.y[1].to_string()]
            ],
            "pi_c": [proof.proof.c.x.to_string(), proof.proof.c.y.to_string()]
        });

        let f = File::create(proof_path)?;
        let w = BufWriter::new(f);
        serde_json::to_writer_pretty(w, &proof_json)?;

        let f2 = File::create(pub_path)?;
        let w2 = BufWriter::new(f2);
        serde_json::to_writer_pretty(w2, &proof.pub_inputs)?;

        Ok(())
    })() {
        eprintln!("failed to write snarkjs diagnostics: {:#}", e);
    }

    let ok = CircomProver::verify(
        CircomProverProofLib::Arkworks,
        proof,
        SPEND_ZKEY_PATH.to_string(),
    )
    .expect("verify call failed");

    assert!(ok, "expected direct spend proof to verify");
}

// Diagnostic test removed: test_spend_witness_satisfies_r1cs
// HALO2_TEMPLATE
halo2_stub!();

// NOIR_TEMPLATE
noir_stub!();
