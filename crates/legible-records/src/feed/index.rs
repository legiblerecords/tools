//! The feed index, `feed.json` (`spec/feeds.md` § `feed.json`).

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::sign::is_publisher;
use crate::time;

/// The feed index's `$type`.
pub const FEED_TYPE: &str = "org.legiblerecords.feed";

/// One stream of a feed index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamEntry {
    pub id: String,
    pub title: String,
    pub record_types: Vec<String>,
    /// The bundle's path from the feed's base.
    pub bundle: String,
    /// Of the bundle file as stored (the ciphertext, for an encrypted feed).
    pub sha256: String,
    pub published_at: String,
}

/// A feed index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Feed {
    pub id: String,
    pub publisher: String,
    pub audience: String,
    pub updated_at: String,
    pub streams: Vec<StreamEntry>,
}

/// Whether `s` is a `common.slug`: lowercase letters and digits in groups
/// joined by single hyphens.
pub fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.split('-').all(|group| {
            !group.is_empty()
                && group
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

/// Whether `s` is a feed id, `<publisher>/<slug>`.
pub fn is_feed_id(s: &str) -> bool {
    s.split_once('/')
        .is_some_and(|(publisher, slug)| is_publisher(publisher) && is_slug(slug))
}

/// Whether `s` is a SHA-256 as lowercase hex.
pub fn is_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub(crate) fn string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    match object.get(name) {
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(format!("{name} must be a string")),
        None => Err(format!("{name} is missing")),
    }
}

fn instant(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    let s = string(object, name)?;
    time::parse(s).map_err(|e| format!("{name}: {e}"))?;
    Ok(s.to_owned())
}

fn stream_entry(value: &Value, index: usize) -> Result<StreamEntry, String> {
    let at = |e: String| format!("streams[{index}]: {e}");
    let object = value
        .as_object()
        .ok_or_else(|| at("must be an object".to_owned()))?;
    let id = string(object, "id").map_err(at)?;
    if !is_slug(id) {
        return Err(at(format!("id {id:?} is not a slug")));
    }
    let title = string(object, "title").map_err(at)?;
    let record_types = object
        .get("record_types")
        .and_then(Value::as_array)
        .ok_or_else(|| at("record_types must be a list of strings".to_owned()))?
        .iter()
        .map(|t| t.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| at("record_types must be a list of strings".to_owned()))?;
    let bundle = string(object, "bundle").map_err(at)?;
    let named = bundle
        .strip_prefix("bundles/")
        .and_then(|rest| {
            rest.strip_suffix(".zip")
                .or_else(|| rest.strip_suffix(".zip.age"))
        })
        .is_some_and(is_sha256);
    if !named {
        return Err(at(format!(
            "bundle {bundle:?} is not bundles/<sha256>.zip or .zip.age"
        )));
    }
    let sha256 = string(object, "sha256").map_err(at)?;
    if !is_sha256(sha256) {
        return Err(at("sha256 is not 64 lowercase hex digits".to_owned()));
    }
    Ok(StreamEntry {
        id: id.to_owned(),
        title: title.to_owned(),
        record_types,
        bundle: bundle.to_owned(),
        sha256: sha256.to_owned(),
        published_at: instant(object, "published_at").map_err(at)?,
    })
}

/// Reads a feed index: it must be a valid `org.legiblerecords.feed`, and no
/// stream id may appear twice. Whether each `bundle` names its own hash, in
/// the feed's mode, is [`check_bundle_paths`].
pub fn parse_feed(bytes: &[u8]) -> Result<Feed, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("feed index: not JSON: {e}"))?;
    let object = value.as_object().ok_or("feed index: not a JSON object")?;
    let fail = |e: String| format!("feed index: {e}");
    if string(object, "$type").map_err(fail)? != FEED_TYPE
        || object.get("version") != Some(&Value::from(1))
    {
        return Err(fail(format!("not an {FEED_TYPE} version 1")));
    }
    let id = string(object, "id").map_err(fail)?;
    if !is_feed_id(id) {
        return Err(fail(format!("id {id:?} is not <publisher>/<slug>")));
    }
    let publisher = string(object, "publisher").map_err(fail)?;
    if !is_publisher(publisher) {
        return Err(fail(format!("publisher {publisher:?} is not a domain")));
    }
    let audience = string(object, "audience").map_err(fail)?;
    let updated_at = instant(object, "updated_at").map_err(fail)?;
    let listed = object
        .get("streams")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("streams must be a list".to_owned()))?;
    let mut streams = Vec::with_capacity(listed.len());
    let mut seen = BTreeSet::new();
    for (index, value) in listed.iter().enumerate() {
        let entry = stream_entry(value, index).map_err(fail)?;
        if !seen.insert(entry.id.clone()) {
            return Err(fail(format!("stream {:?} appears twice", entry.id)));
        }
        streams.push(entry);
    }
    Ok(Feed {
        id: id.to_owned(),
        publisher: publisher.to_owned(),
        audience: audience.to_owned(),
        updated_at,
        streams,
    })
}

/// Checks that every stream's `bundle` is `bundles/<its sha256>.zip`, or
/// `.zip.age` when the feed is encrypted.
pub fn check_bundle_paths(feed: &Feed, encrypted: bool) -> Result<(), String> {
    let suffix = if encrypted { ".zip.age" } else { ".zip" };
    for stream in &feed.streams {
        let expected = format!("bundles/{}{suffix}", stream.sha256);
        if stream.bundle != expected {
            return Err(format!(
                "feed index: stream {:?} lists {:?}, not {expected:?}",
                stream.id, stream.bundle
            ));
        }
    }
    Ok(())
}
