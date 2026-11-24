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
