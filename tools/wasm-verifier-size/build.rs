use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let vector_path = manifest_dir.join("../../vectors/CL-STD-1/kat.json");
    println!("cargo:rerun-if-changed={}", vector_path.display());

    let document: serde_json::Value = serde_json::from_slice(&fs::read(&vector_path)?)?;
    let chain = document
        .get("chains")
        .and_then(serde_json::Value::as_array)
        .and_then(|chains| chains.first())
        .ok_or_else(|| invalid_data("KAT contains no certificate-chain vector"))?;

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    write_hex_field(chain, "root_verifying_key", &out_dir, "root-vk.bin")?;
    write_hex_field(chain, "pinned_root_digest", &out_dir, "root-digest.bin")?;
    write_hex_field(chain, "epoch_envelope", &out_dir, "epoch-envelope.bin")?;
    write_hex_field(
        chain,
        "artifact_envelope",
        &out_dir,
        "artifact-envelope.bin",
    )?;
    Ok(())
}

fn write_hex_field(
    object: &serde_json::Value,
    field: &str,
    out_dir: &Path,
    filename: &str,
) -> Result<(), Box<dyn Error>> {
    let encoded = object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_data(&format!("chain vector lacks {field}")))?;
    let bytes = hex::decode(encoded)?;
    fs::write(out_dir.join(filename), bytes)?;
    Ok(())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
