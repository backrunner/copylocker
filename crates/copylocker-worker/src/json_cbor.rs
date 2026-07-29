use copylocker_suite::cbor::{decode_canonical, CborValue, Limits};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{Map, Number, Value};
use worker::Result;

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;

pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let json = serde_json::to_value(value)?;
    let cbor = from_json(&json, 0).ok_or_else(|| {
        worker::Error::RustError("configuration contains unsupported JSON data".to_owned())
    })?;
    let encoded = cbor.to_canonical();
    if encoded.len() > MAX_SNAPSHOT_BYTES {
        return Err(worker::Error::RustError(
            "configuration snapshot exceeds 256 KiB".to_owned(),
        ));
    }
    Ok(encoded)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(worker::Error::RustError(
            "configuration snapshot exceeds 256 KiB".to_owned(),
        ));
    }
    let value = decode_canonical(
        bytes,
        Limits {
            max_string: MAX_SNAPSHOT_BYTES,
            ..Limits::default()
        },
    )
    .map_err(|_| worker::Error::RustError("configuration snapshot is not canonical".to_owned()))?;
    let json = to_json(&value).ok_or_else(|| {
        worker::Error::RustError("configuration snapshot contains invalid data".to_owned())
    })?;
    serde_json::from_value(json).map_err(|_| {
        worker::Error::RustError("configuration snapshot has the wrong shape".to_owned())
    })
}

fn from_json(value: &Value, depth: u8) -> Option<CborValue> {
    if depth > Limits::default().max_depth {
        return None;
    }
    match value {
        Value::Null => Some(CborValue::Null),
        Value::Bool(value) => Some(CborValue::Bool(*value)),
        Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                (value <= MAX_SAFE_INTEGER as u64).then_some(CborValue::Uint(value))
            } else {
                value
                    .as_i64()
                    .filter(|value| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(value))
                    .map(CborValue::int)
            }
        }
        Value::String(value) => {
            (value.len() <= MAX_SNAPSHOT_BYTES).then(|| CborValue::Text(value.clone()))
        }
        Value::Array(values) => {
            if values.len() > Limits::default().max_items {
                return None;
            }
            values
                .iter()
                .map(|value| from_json(value, depth.saturating_add(1)))
                .collect::<Option<Vec<_>>>()
                .map(CborValue::Array)
        }
        Value::Object(values) => {
            if values.len() > Limits::default().max_items {
                return None;
            }
            values
                .iter()
                .map(|(key, value)| {
                    (key.len() <= MAX_SNAPSHOT_BYTES).then(|| {
                        Some((
                            CborValue::Text(key.clone()),
                            from_json(value, depth.saturating_add(1))?,
                        ))
                    })?
                })
                .collect::<Option<Vec<_>>>()
                .map(CborValue::Map)
        }
    }
}

fn to_json(value: &CborValue) -> Option<Value> {
    match value {
        CborValue::Uint(value) => {
            (*value <= MAX_SAFE_INTEGER as u64).then(|| Value::Number(Number::from(*value)))
        }
        CborValue::Nint(_) => value
            .as_int()
            .filter(|value| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(value))
            .map(Number::from)
            .map(Value::Number),
        CborValue::Bytes(_) => None,
        CborValue::Text(value) => Some(Value::String(value.clone())),
        CborValue::Array(values) => values
            .iter()
            .map(to_json)
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        CborValue::Map(values) => {
            let mut map = Map::new();
            for (key, value) in values {
                let key = key.as_text()?.to_owned();
                if map.insert(key, to_json(value)?).is_some() {
                    return None;
                }
            }
            Some(Value::Object(map))
        }
        CborValue::Bool(value) => Some(Value::Bool(*value)),
        CborValue::Null => Some(Value::Null),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_structured_json_canonically() -> Result<()> {
        let value = serde_json::json!({
            "z": [true, null, -4],
            "a": {"name": "feature", "version": 3}
        });
        let first = encode(&value)?;
        let second = encode(&value)?;
        assert_eq!(first, second);
        assert_eq!(decode::<Value>(&first)?, value);
        Ok(())
    }

    #[test]
    fn rejects_floating_point_values() {
        assert!(encode(&serde_json::json!({"ratio": 0.5})).is_err());
    }
}
