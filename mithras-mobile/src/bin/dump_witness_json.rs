use std::fs;

use circom_prover::witness::{generate_witness, WitnessFn};

// The package build script generates a static archive named `libcircuit.a` containing the
// transpiled Circom WASM witness code. The library/tests already link it via rust-witness,
// but this standalone debug binary needs an explicit link to resolve the extern symbols.
#[link(name = "circuit", kind = "static")]
extern "C" {}

mod witness {
    rust_witness::witness!(multiplier2);
    rust_witness::witness!(multiplier2bls);
    rust_witness::witness!(deposit);
    rust_witness::witness!(spend);
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let circuit_key = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: dump_witness_json <circuit-key> <input.json>"))?;
    let input_path = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: dump_witness_json <circuit-key> <input.json>"))?;

    if args.next().is_some() {
        anyhow::bail!("usage: dump_witness_json <circuit-key> <input.json>");
    }

    let input = fs::read_to_string(&input_path)?;

    let witness_fn = match circuit_key.as_str() {
        "multiplier2_final.zkey" | "multiplier2" => {
            WitnessFn::RustWitness(witness::multiplier2_witness)
        }
        "multiplier2_bls_final.zkey" | "multiplier2_bls" | "multiplier2bls" => {
            WitnessFn::RustWitness(witness::multiplier2bls_witness)
        }
        "deposit_test.zkey" | "deposit" => WitnessFn::RustWitness(witness::deposit_witness),
        "spend_test.zkey" | "spend" => WitnessFn::RustWitness(witness::spend_witness),
        other => anyhow::bail!("unknown circuit key: {other}"),
    };

    let witness_thread = generate_witness(witness_fn, input);
    let witness = witness_thread.join().expect("witness thread panicked");

    let witness_as_dec_strings = witness
        .into_iter()
        .map(|v| v.to_str_radix(10))
        .collect::<Vec<_>>();

    serde_json::to_writer(std::io::stdout(), &witness_as_dec_strings)?;
    Ok(())
}
