//! Publishing (`spec/feeds.md` § Publishing): the parts of it that need no
//! I/O. `legible feed publish` does the writing.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{json, Value};

use super::index::{Feed, FEED_TYPE};
use crate::bundle::canonical_record;
use crate::time::{self, Instant};

/// The `$type` of a publisher's state file.
pub const PUBLISH_STATE_TYPE: &str = "legible-publish-state";

/// The later of `now` and one millisecond after `previous`, written as
/// `published_at` and `updated_at` are: UTC, with milliseconds. A reader
/// refuses a `published_at` that isn't strictly later than the last, so two
/// publishes in the same millisecond must still differ. A `previous` that
/// isn't an instant is ignored.
pub fn next_published_at(now: Instant, previous: Option<&str>) -> String {
    let now = now.truncated_to_millis();
    let after_previous = previous
        .and_then(|p| time::parse(p).ok())
        .map(|p| p.truncated_to_millis().plus_millis(1));
    match after_previous {
        Some(later) if later > now => time::format(later),
        _ => time::format(now),
    }
}

/// What a publisher keeps between publishes: when each bundle lost its last
/// stream, so it is deleted only after a grace period; each stream's last
/// `published_at`, so a stream withdrawn and published again, or an index
/// rebuilt, never goes back in time; and the last index's `updated_at`, so a
/// rebuilt index isn't older than the one readers hold (`stale_feed`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublishState {
    /// Bundle path to when it lost its last stream.
    pub unreferenced_since: BTreeMap<String, String>,
    /// Stream id to the last `published_at` published for it. A state file
    /// written before this was kept has none.
    pub published_at: BTreeMap<String, String>,
    /// The `updated_at` of the last index published. A state file written
    /// before this was kept has none.
    pub updated_at: Option<String>,
}

impl PublishState {
    /// Reads a state file.
    pub fn parse(bytes: &[u8]) -> Result<PublishState, String> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|e| format!("not a publish state file: {e}"))?;
        if value.get("$type") != Some(&json!(PUBLISH_STATE_TYPE))
            || value.get("version") != Some(&json!(1))
        {
            return Err(format!(
                "not a publish state file: not a {PUBLISH_STATE_TYPE} version 1"
            ));
        }
        let listed = value
            .get("unreferenced_since")
            .and_then(Value::as_object)
            .ok_or("not a publish state file: unreferenced_since must be an object")?;
        let mut unreferenced_since = BTreeMap::new();
        for (path, since) in listed {
            let since = since
                .as_str()
                .ok_or_else(|| format!("unreferenced_since[{path:?}] must be a string"))?;
            time::parse(since).map_err(|e| format!("unreferenced_since[{path:?}]: {e}"))?;
            unreferenced_since.insert(path.clone(), since.to_owned());
        }
        let mut published_at = BTreeMap::new();
        if let Some(listed) = value.get("published_at") {
            let listed = listed
                .as_object()
                .ok_or("not a publish state file: published_at must be an object")?;
            for (stream, at) in listed {
                let at = at
                    .as_str()
                    .ok_or_else(|| format!("published_at[{stream:?}] must be a string"))?;
                time::parse(at).map_err(|e| format!("published_at[{stream:?}]: {e}"))?;
                published_at.insert(stream.clone(), at.to_owned());
            }
        }
        let updated_at = match value.get("updated_at") {
            None | Some(Value::Null) => None,
            Some(at) => {
                let at = at
                    .as_str()
                    .ok_or("not a publish state file: updated_at must be a string")?;
                time::parse(at).map_err(|e| format!("updated_at: {e}"))?;
                Some(at.to_owned())
            }
        };
        Ok(PublishState {
            unreferenced_since,
            published_at,
            updated_at,
        })
    }

    /// The state file's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut value = json!({
            "$type": PUBLISH_STATE_TYPE,
            "version": 1,
            "unreferenced_since": self.unreferenced_since,
            "published_at": self.published_at,
        });
        if let Some(at) = &self.updated_at {
            value["updated_at"] = json!(at);
        }
        canonical_record(&value)
    }
}

/// The bundles that have gone unreferenced for at least `grace`, so may be
/// deleted. One whose date can't be read is kept.
pub fn collectable(state: &PublishState, now: Instant, grace: Duration) -> Vec<String> {
    let grace_ms = i64::try_from(grace.as_millis()).unwrap_or(i64::MAX);
    state
        .unreferenced_since
        .iter()
        .filter(|(_, since)| {
            time::parse(since).is_ok_and(|since| since.plus_millis(grace_ms) <= now)
        })
        .map(|(path, _)| path.clone())
        .collect()
}

/// A feed index as a publisher writes it: sorted keys, two-space
/// indentation, a final newline.
pub fn render_feed(feed: &Feed) -> Vec<u8> {
    let streams: Vec<Value> = feed
        .streams
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "title": s.title,
                "record_types": s.record_types,
                "bundle": s.bundle,
                "sha256": s.sha256,
                "published_at": s.published_at,
            })
        })
        .collect();
    canonical_record(&json!({
        "$type": FEED_TYPE,
        "version": 1,
        "id": feed.id,
        "publisher": feed.publisher,
        "audience": feed.audience,
        "updated_at": feed.updated_at,
        "streams": streams,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> Instant {
        time::parse(s).unwrap()
    }

    #[test]
    fn same_instant_is_one_millisecond_later() {
        let t = at("2026-11-24T10:00:00.250Z");
        let first = next_published_at(t, None);
        assert_eq!(first, "2026-11-24T10:00:00.250Z");
        let second = next_published_at(t, Some(&first));
        assert_eq!(second, "2026-11-24T10:00:00.251Z");
        assert!(time::parse(&second).unwrap() > time::parse(&first).unwrap());
    }

    #[test]
    fn sub_millisecond_now_does_not_tie_with_previous() {
        // now is later than previous by 400 microseconds, but they format alike.
        let now = at("2026-11-24T10:00:00.250400Z");
        let next = next_published_at(now, Some("2026-11-24T10:00:00.250Z"));
        assert_eq!(next, "2026-11-24T10:00:00.251Z");
    }

    #[test]
    fn later_now_wins_and_other_offsets_compare_as_instants() {
        let now = at("2026-11-24T10:00:05Z");
        assert_eq!(
            next_published_at(now, Some("2026-11-24T10:00:00Z")),
            "2026-11-24T10:00:05.000Z"
        );
        // 11:00:00+01:00 is 10:00:00Z.
        assert_eq!(
            next_published_at(
                at("2026-11-24T10:00:00Z"),
                Some("2026-11-24T11:00:00+01:00")
            ),
            "2026-11-24T10:00:00.001Z"
        );
    }

    #[test]
    fn previous_in_the_future_is_followed() {
        let now = at("2026-11-24T10:00:00Z");
        assert_eq!(
            next_published_at(now, Some("2026-11-24T12:00:00Z")),
            "2026-11-24T12:00:00.001Z"
        );
        assert_eq!(
            next_published_at(now, Some("garbage")),
            "2026-11-24T10:00:00.000Z"
        );
    }

    #[test]
    fn collectable_waits_for_the_grace() {
        let mut state = PublishState::default();
        state
            .unreferenced_since
            .insert("bundles/a.zip".into(), "2026-11-24T10:00:00Z".into());
        state
            .unreferenced_since
            .insert("bundles/b.zip".into(), "2026-11-24T10:30:00Z".into());
        let hour = Duration::from_secs(3600);
        assert!(collectable(&state, at("2026-11-24T10:59:59Z"), hour).is_empty());
        assert_eq!(
            collectable(&state, at("2026-11-24T11:00:00Z"), hour),
            ["bundles/a.zip"]
        );
        assert_eq!(
            collectable(&state, at("2026-11-24T11:30:00Z"), hour),
            ["bundles/a.zip", "bundles/b.zip"]
        );
    }

    #[test]
    fn state_round_trips_and_refuses_other_files() {
        let mut state = PublishState::default();
        state
            .unreferenced_since
            .insert("bundles/a.zip".into(), "2026-11-24T10:00:00.000Z".into());
        state
            .published_at
            .insert("main".into(), "2026-11-24T10:00:00.000Z".into());
        assert_eq!(PublishState::parse(&state.to_bytes()).unwrap(), state);
        state.updated_at = Some("2026-11-24T10:00:00.001Z".into());
        assert_eq!(PublishState::parse(&state.to_bytes()).unwrap(), state);
        // A file from before published_at was kept still reads.
        let old = br#"{"$type":"legible-publish-state","version":1,"unreferenced_since":{}}"#;
        assert_eq!(PublishState::parse(old).unwrap(), PublishState::default());
        assert!(PublishState::parse(b"{}").is_err());
        assert!(PublishState::parse(b"nope").is_err());
    }
}
