//! Reader state (`spec/feeds.md` § Reader state): what a reader remembers
//! between polls, in the form the vectors use, with `"$type":
//! "legible-reader-state"` and `"version": 1` on disk.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use super::index::{is_sha256, is_slug, string};
use crate::bundle::canonical_record;
use crate::keys::{KeySet, Pin};
use crate::sign::{b64url, from_b64url, is_key_id, is_publisher};
use crate::time;

/// The state file's `$type`.
pub const STATE_TYPE: &str = "legible-reader-state";

/// A stream's last accepted bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamState {
    pub sha256: String,
    pub published_at: String,
}

/// What a reader keeps about one feed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReaderState {
    /// `updated_at` of the last accepted feed index.
    pub feed_updated_at: Option<String>,
    /// Each stream's last accepted bundle.
    pub streams: BTreeMap<String, StreamState>,
    /// The last accepted key set, by its publisher.
    pub key_sets: BTreeMap<String, KeySet>,
    /// Keys a person approved.
    pub approved: Vec<Pin>,
}

fn instant(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    let s = string(object, name)?;
    time::parse(s)?;
    Ok(s.to_owned())
}

fn approved_pin(value: &Value, index: usize) -> Result<Pin, String> {
    let place = format!("approved[{index}]");
    let object = value
        .as_object()
        .ok_or_else(|| format!("{place} must be an object"))?;
    let at = |e: String| format!("{place}.{e}");
    let publisher = string(object, "publisher").map_err(at)?;
    let id = string(object, "id").map_err(at)?;
    if !is_publisher(publisher) || !is_key_id(id) {
        return Err(format!("{place}: not a publisher and key id"));
    }
    if object
        .get("alg")
        .is_some_and(|alg| alg.as_str() != Some("ed25519"))
    {
        return Err(format!("{place}.alg is not ed25519"));
    }
    let public_key = from_b64url(string(object, "public_key").map_err(at)?)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| format!("{place}.public_key is not 32 bytes of base64url"))?;
    Ok(Pin {
        publisher: publisher.to_owned(),
        id: id.to_owned(),
        public_key,
    })
}

impl ReaderState {
    /// Reads a state file.
    pub fn parse(bytes: &[u8]) -> Result<ReaderState, String> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|e| format!("reader state: not JSON: {e}"))?;
        let object = value.as_object().ok_or("reader state: not a JSON object")?;
        let inner = || -> Result<ReaderState, String> {
            if object.get("$type").and_then(Value::as_str) != Some(STATE_TYPE)
                || object.get("version") != Some(&Value::from(1))
            {
                return Err(format!("not a {STATE_TYPE} version 1"));
            }
            let feed_updated_at = match object.get("feed_updated_at") {
                None | Some(Value::Null) => None,
                Some(_) => Some(instant(object, "feed_updated_at")?),
            };
            let mut streams = BTreeMap::new();
            let listed = match object.get("streams") {
                None => &Map::new(),
                Some(v) => v.as_object().ok_or("streams must be an object")?,
            };
            for (id, stream) in listed {
                let at = |e: String| format!("streams.{id}: {e}");
                if !is_slug(id) {
                    return Err(at("not a slug".to_owned()));
                }
                let stream = stream
                    .as_object()
                    .ok_or_else(|| at("must be an object".to_owned()))?;
                let sha256 = string(stream, "sha256").map_err(at)?;
                if !is_sha256(sha256) {
                    return Err(at("sha256 is not 64 lowercase hex digits".to_owned()));
                }
                streams.insert(
                    id.clone(),
                    StreamState {
                        sha256: sha256.to_owned(),
                        published_at: instant(stream, "published_at").map_err(at)?,
                    },
                );
            }
            let mut key_sets = BTreeMap::new();
            let held = match object.get("key_sets") {
                None => &Map::new(),
                Some(v) => v.as_object().ok_or("key_sets must be an object")?,
            };
            for (publisher, set) in held {
                let bytes = serde_json::to_vec(set).expect("JSON values serialize");
                let set = KeySet::parse(&bytes)
                    .map_err(|code| format!("key_sets.{publisher}: {code}"))?;
                if &set.publisher != publisher {
                    return Err(format!(
                        "key_sets.{publisher} holds {}'s key set",
                        set.publisher
                    ));
                }
                key_sets.insert(publisher.clone(), set);
            }
            let approved = match object.get("approved") {
                None => Vec::new(),
                Some(v) => v
                    .as_array()
                    .ok_or("approved must be a list")?
                    .iter()
                    .enumerate()
                    .map(|(i, p)| approved_pin(p, i))
                    .collect::<Result<_, _>>()?,
            };
            Ok(ReaderState {
                feed_updated_at,
                streams,
                key_sets,
                approved,
            })
        };
        inner().map_err(|e| format!("reader state: {e}"))
    }

    /// The state file's bytes: sorted keys, two-space indents.
    pub fn to_bytes(&self) -> Vec<u8> {
        let streams: Map<String, Value> = self
            .streams
            .iter()
            .map(|(id, s)| {
                (
                    id.clone(),
                    json!({"sha256": s.sha256, "published_at": s.published_at}),
                )
            })
            .collect();
        let key_sets: Map<String, Value> = self
            .key_sets
            .iter()
            .map(|(publisher, set)| {
                // A held set was parsed from these bytes, so they are JSON.
                let value: Value = serde_json::from_slice(&set.bytes).unwrap_or(Value::Null);
                (publisher.clone(), value)
            })
            .collect();
        let approved: Vec<Value> = self
            .approved
            .iter()
            .map(|p| {
                json!({"publisher": p.publisher, "id": p.id, "alg": "ed25519",
                       "public_key": b64url(&p.public_key)})
            })
            .collect();
        canonical_record(&json!({
            "$type": STATE_TYPE,
            "version": 1,
            "feed_updated_at": self.feed_updated_at,
            "streams": streams,
            "key_sets": key_sets,
            "approved": approved,
        }))
    }
}
