use std::error::Error;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    tauri_build::build();

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let vector_path = manifest.join("../../../vectors/CL-STD-1/kat.json");
    let vector: serde_json::Value = serde_json::from_str(&fs::read_to_string(&vector_path)?)?;
    let public_key = vector
        .get("signatures")
        .and_then(|value| value.get(0))
        .and_then(|value| value.get("verifying_key"))
        .and_then(serde_json::Value::as_str)
        .ok_or("KAT does not contain a public verifying key")?;
    let bytes = hex::decode(public_key)?;
    let output = PathBuf::from(std::env::var("OUT_DIR")?).join("development-root-key.bin");
    fs::write(output, bytes)?;
    println!("cargo:rerun-if-changed={}", vector_path.display());
    Ok(())
}
