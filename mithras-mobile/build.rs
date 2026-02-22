fn main() {
    // CIRCOM_TEMPLATE

    use std::fs;
    use std::path::{Path, PathBuf};

    let out_dir = std::env::var_os("OUT_DIR").expect("OUT_DIR not set");
    let out_dir: PathBuf = PathBuf::from(out_dir);

    let stage_dir: PathBuf = out_dir.join("circom_wasm");
    let _ = fs::remove_dir_all(&stage_dir);
    fs::create_dir_all(&stage_dir).expect("failed to create circom_wasm staging dir");

    // Only stage wasm from the local test-vectors directory.
    let sources: [&Path; 1] = [Path::new("./test-vectors/circom")];

    for dir in sources.iter() {
        println!("cargo:rerun-if-changed={}", dir.display());

        let entries = fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("failed to read_dir {}: {e}", dir.display()));
        for entry in entries {
            let entry = entry.expect("failed to read dir entry");
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
                continue;
            }

            let file_name = path
                .file_name()
                .expect("wasm path missing file_name")
                .to_owned();
            let dest = stage_dir.join(file_name);
            fs::copy(&path, &dest).unwrap_or_else(|e| {
                panic!(
                    "failed to copy wasm from {} to {}: {e}",
                    path.display(),
                    dest.display()
                )
            });
        }
    }

    rust_witness::transpile::transpile_wasm(stage_dir.to_string_lossy().to_string());
}
