//! A record's content line and content hash (spec/records.md § Content
//! lines): its canonical line without the top-level provenance fields
//! `produced_by` and `source`, so republishing unchanged content keeps its
//! hash. An external reference's `sha256` is this hash.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::record_set::canonical_line;

/// The top-level fields a content line leaves out.
pub const PROVENANCE: [&str; 2] = ["produced_by", "source"];

/// The record's content line, without a trailing `\n`.
pub fn content_line(record: &Value) -> Vec<u8> {
    let mut line = match record {
        Value::Object(map) => {
            let mut content = map.clone();
            for field in PROVENANCE {
                content.remove(field);
            }
            canonical_line(&Value::Object(content))
        }
        other => canonical_line(other),
    };
    line.pop();
    line
}

/// The SHA-256 of the record's content line, in lowercase hex.
pub fn content_sha256(record: &Value) -> String {
    Sha256::digest(content_line(record))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Parses a record's text strictly, refusing what has no canonical form
/// (spec/records.md § Content lines): text that isn't a JSON object, a key
/// that appears twice in an object, an integer a double can't hold exactly,
/// or a lone surrogate.
pub fn parse(text: &[u8]) -> Result<Value, String> {
    if let Some(token) = inexact_integer(text) {
        return Err(format!("{token} can't be held exactly as a double"));
    }
    let Strict(value) = serde_json::from_slice(text).map_err(|e| e.to_string())?;
    if !value.is_object() {
        return Err("not a JSON object".to_owned());
    }
    Ok(value)
}

/// The first integer token outside strings that a double doesn't hold exactly.
fn inexact_integer(text: &[u8]) -> Option<String> {
    let (mut i, mut in_string) = (0, false);
    while i < text.len() {
        let b = text[i];
        if in_string {
            match b {
                b'\\' => i += 1,
                b'"' => in_string = false,
                _ => {}
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        if b == b'-' || b.is_ascii_digit() {
            let start = i;
            while i < text.len()
                && matches!(text[i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
            {
                i += 1;
            }
            let token = std::str::from_utf8(&text[start..i]).ok()?;
            let digits = token.trim_start_matches('-');
            if !token.contains(['.', 'e', 'E']) && digits.len() > 15 {
                let exact = token
                    .parse::<f64>()
                    .is_ok_and(|x| format!("{:.0}", x.abs()) == digits.trim_start_matches('0'));
                if !exact {
                    return Some(token.to_owned());
                }
            }
            continue;
        }
        i += 1;
    }
    None
}

/// A JSON value whose objects have no repeated key.
struct Strict(Value);

impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("not a finite number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let Strict(value) = map.next_value()?;
            if object.insert(key.clone(), value).is_some() {
                return Err(serde::de::Error::custom(format!(
                    "the key {key:?} appears twice"
                )));
            }
        }
        Ok(Value::Object(object))
    }
}
