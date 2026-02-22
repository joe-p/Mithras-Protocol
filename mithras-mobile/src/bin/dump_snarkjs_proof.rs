use mithras_mobile::{generate_circom_proof, ProofLib};
use serde_json::json;
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: dump_snarkjs_proof <zkey_path> <inputs.json> [out_prefix]\n\n");
        std::process::exit(2);
    }

    let zkey_path = args[1].clone();
    let inputs_path = args[2].clone();
    let out_prefix = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "/tmp/mithras".to_string());

    let inputs_str = fs::read_to_string(&inputs_path)
        .unwrap_or_else(|e| panic!("failed to read inputs file {}: {e}", inputs_path));

    let result = generate_circom_proof(zkey_path.clone(), inputs_str, ProofLib::Arkworks)
        .unwrap_or_else(|e| panic!("prove failed: {e:?}"));

    let proof = result.proof;

    // Match snarkjs groth16 proof.json schema:
    // { pi_a: [ax,ay,az], pi_b: [[bx0,bx1],[by0,by1],[bz0,bz1]], pi_c: [cx,cy,cz], protocol, curve }
    // where Fq2 elements are encoded as [c0, c1].
    let proof_json = json!({
        "pi_a": [proof.a.x, proof.a.y, proof.a.z],
        "pi_b": [
            [proof.b.x[0].clone(), proof.b.x[1].clone()],
            [proof.b.y[0].clone(), proof.b.y[1].clone()],
            [proof.b.z[0].clone(), proof.b.z[1].clone()],
        ],
        "pi_c": [proof.c.x, proof.c.y, proof.c.z],
        "protocol": proof.protocol,
        "curve": proof.curve,
    });

    let public_json = serde_json::Value::Array(
        result
            .inputs
            .into_iter()
            .map(serde_json::Value::String)
            .collect(),
    );

    let out_proof = format!("{}_proof.json", out_prefix);
    let out_public = format!("{}_public.json", out_prefix);

    fs::write(
        &out_proof,
        serde_json::to_string_pretty(&proof_json).unwrap(),
    )
    .unwrap_or_else(|e| panic!("failed to write {out_proof}: {e}"));
    fs::write(
        &out_public,
        serde_json::to_string_pretty(&public_json).unwrap(),
    )
    .unwrap_or_else(|e| panic!("failed to write {out_public}: {e}"));

    println!("zkey: {}", zkey_path);
    println!("inputs: {}", inputs_path);
    println!("wrote: {}", out_proof);
    println!("wrote: {}", out_public);

    let zkey_name = Path::new(&zkey_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("<unknown>");
    println!("zkey basename: {}", zkey_name);
}
