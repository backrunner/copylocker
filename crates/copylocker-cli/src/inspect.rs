use std::fs;
use std::path::PathBuf;

use clap::Args;
use copylocker_proto::{Envelope, BULK_LIMITS};
use copylocker_suite::cbor::{decode_canonical, CborValue};
use copylocker_suite::HashScheme;
use copylocker_suite_std::Sha256Scheme;
use serde_json::{json, Map, Value};

use crate::{CliError, Output};

const MAX_INSPECT_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Args)]
pub(crate) struct InspectArgs {
    /// Canonical CBOR artifact or signed Envelope file.
    pub(crate) artifact: PathBuf,
    /// Treat the file as whitespace-surrounded hexadecimal text instead of raw bytes.
    #[arg(long)]
    pub(crate) hex: bool,
}

pub(crate) fn run(args: &InspectArgs) -> Result<Output, CliError> {
    let metadata = fs::metadata(&args.artifact)
        .map_err(|error| CliError::io("inspect", &args.artifact, &error))?;
    if metadata.len() > MAX_INSPECT_BYTES {
        return Err(CliError::new(
            "artifact_too_large",
            format!(
                "{} is {} bytes; inspect accepts at most {} bytes",
                args.artifact.display(),
                metadata.len(),
                MAX_INSPECT_BYTES
            ),
        ));
    }
    let encoded =
        fs::read(&args.artifact).map_err(|error| CliError::io("read", &args.artifact, &error))?;
    let bytes = if args.hex {
        let text = std::str::from_utf8(&encoded).map_err(|_| {
            CliError::new(
                "invalid_hex_artifact",
                format!("{} is not UTF-8 hexadecimal text", args.artifact.display()),
            )
        })?;
        hex::decode(text.trim()).map_err(|_| {
            CliError::new(
                "invalid_hex_artifact",
                format!("{} is not valid hexadecimal text", args.artifact.display()),
            )
        })?
    } else {
        encoded
    };
    if bytes.is_empty() {
        return Err(CliError::new(
            "empty_artifact",
            format!("{} is empty", args.artifact.display()),
        ));
    }

    let digest = Sha256Scheme::hash(&bytes).to_hex();
    let inspected = match Envelope::decode(&bytes) {
        Ok(envelope) => inspect_envelope(&envelope)?,
        Err(_) => {
            let body = decode_canonical(&bytes, BULK_LIMITS).map_err(|error| {
                CliError::new(
                    "invalid_artifact",
                    format!(
                        "{} is neither a signed Envelope nor canonical CopyLocker CBOR: {error:?}",
                        args.artifact.display()
                    ),
                )
            })?;
            json!({
                "container": "canonical_cbor",
                "verified": false,
                "decoded": cbor_to_json(&body)
            })
        }
    };
    let result = json!({
        "ok": true,
        "command": "inspect",
        "path": args.artifact,
        "input_encoding": if args.hex { "hex" } else { "binary" },
        "bytes": bytes.len(),
        "sha256": digest,
        "trusted": false,
        "notice": "inspection decodes canonical bytes but does not establish signature trust",
        "artifact": inspected
    });
    let human = serde_json::to_string_pretty(&result).map_err(|error| {
        CliError::new(
            "json_encode_failed",
            format!("failed to render inspected artifact: {error}"),
        )
    })?;
    Ok(Output {
        human,
        json: result,
    })
}

fn inspect_envelope(envelope: &Envelope) -> Result<Value, CliError> {
    let body = decode_canonical(&envelope.tbs, BULK_LIMITS).map_err(|error| {
        CliError::new(
            "invalid_envelope_body",
            format!("Envelope contains a non-canonical artifact body: {error:?}"),
        )
    })?;
    Ok(json!({
        "container": "envelope",
        "verified": false,
        "proto_ver": envelope.proto_ver,
        "suite_id": envelope.suite_id.to_string(),
        "artifact_kind": envelope.kind.ctx_name(),
        "epoch_ref": envelope.epoch_ref.map(|epoch| epoch.to_hex()),
        "signature": byte_value(&envelope.sig),
        "canonical_body_bytes": envelope.tbs.len(),
        "decoded": cbor_to_json(&body)
    }))
}

fn cbor_to_json(value: &CborValue) -> Value {
    match value {
        CborValue::Uint(value) => json!(value),
        CborValue::Nint(_) => value.as_int().map_or_else(
            || json!({ "$negative_integer": format!("{value:?}") }),
            Value::from,
        ),
        CborValue::Bytes(bytes) => byte_value(bytes),
        CborValue::Text(text) => Value::String(text.clone()),
        CborValue::Array(values) => Value::Array(values.iter().map(cbor_to_json).collect()),
        CborValue::Map(entries) if entries.iter().all(|(key, _)| key.as_uint().is_some()) => {
            let mut object = Map::new();
            for (key, value) in entries {
                if let Some(key) = key.as_uint() {
                    object.insert(key.to_string(), cbor_to_json(value));
                }
            }
            Value::Object(object)
        }
        CborValue::Map(entries) if entries.iter().all(|(key, _)| key.as_text().is_some()) => {
            let mut object = Map::new();
            for (key, value) in entries {
                if let Some(key) = key.as_text() {
                    object.insert(key.to_owned(), cbor_to_json(value));
                }
            }
            Value::Object(object)
        }
        CborValue::Map(entries) => json!({
            "$map": entries
                .iter()
                .map(|(key, value)| json!({
                    "key": cbor_to_json(key),
                    "value": cbor_to_json(value)
                }))
                .collect::<Vec<_>>()
        }),
        CborValue::Bool(value) => Value::Bool(*value),
        CborValue::Null => Value::Null,
    }
}

fn byte_value(bytes: &[u8]) -> Value {
    json!({
        "$bytes": hex::encode(bytes),
        "length": bytes.len()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_map_keys_remain_lossless() {
        let value = CborValue::Map(vec![
            (CborValue::Uint(1), CborValue::Text("number".into())),
            (CborValue::Text("1".into()), CborValue::Text("text".into())),
        ]);
        let rendered = cbor_to_json(&value);
        assert_eq!(
            rendered.get("$map").and_then(Value::as_array).map(Vec::len),
            Some(2)
        );
    }

    #[test]
    fn byte_strings_include_length_and_hex() {
        assert_eq!(
            byte_value(&[0xde, 0xad]),
            json!({ "$bytes": "dead", "length": 2 })
        );
    }
}
