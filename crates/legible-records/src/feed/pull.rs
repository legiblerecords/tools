//! Reading a feed (`spec/feeds.md` § Reading a feed, § Reader state): one
//! poll, over a [`Source`] and a [`KeySource`], with no I/O of its own.

use std::collections::BTreeMap;

use super::connection::Connection;
use super::index::{check_bundle_paths, parse_feed, Feed, StreamEntry};
use super::source::{Fetched, KeySource, Source};
use super::state::{ReaderState, StreamState};
use super::MAX_INDEX_BYTES;
use crate::bundle::{
    check_signature, check_signed, open, sha256_hex, verify, Limits, Opened, SignatureStatus,
};
use crate::code::Code;
use crate::keys::{accept_key_set, KeySet, KeySetDecision, Pin, Trust};
use crate::sign::Context;
use crate::time;

/// A bundle `pull` accepted, for its destination.
///
/// A stateless reader's destination does the history checks itself, so each
/// delivery carries what they need: the bundle's `published_at` and
/// `sha256` (in `stream`), and the index's `updated_at` and stream ids. The
/// destination refuses an index older than the last it accepted and marks
/// nothing withdrawn from it, ignores an unchanged hash, refuses a bundle
/// older than the one it holds or as old with a different hash (a replay),
/// and marks withdrawn the streams a newer index no longer lists.
#[derive(Clone, Debug)]
pub struct Delivered {
    /// The stream's entry in the index.
    pub stream: StreamEntry,
    pub bundle: Opened,
    pub signature: SignatureStatus,
    /// The bundle's `published_at`: its manifest's, or for an unsigned
    /// bundle without one, the index entry's.
    pub published_at: String,
    /// The index's `updated_at`.
    pub feed_updated_at: String,
    /// Every stream the index lists, in its order.
    pub stream_ids: Vec<String>,
}

/// What became of one stream in a poll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamOutcome {
    /// Checked and delivered; it is now the stream's current bundle.
    Accepted,
    /// Its `sha256` is the last one accepted, so it wasn't fetched.
    Unchanged,
    /// In the last accepted index and not in this one.
    Withdrawn,
    /// Refused with an outcome code.
    Refused(Code),
    /// Couldn't be fetched or delivered; it is tried again next poll.
    Failed(String),
}

/// What became of the feed index in a poll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexOutcome {
    /// Accepted; the streams were checked.
    Accepted,
    /// The source says it is unchanged since the ETag sent: nothing to do.
    NotModified,
    /// Refused with an outcome code. Nothing changed.
    Refused(Code),
    /// Couldn't be fetched or read. Nothing changed.
    Failed(String),
}

/// What a poll found.
#[derive(Clone, Debug)]
pub struct PullReport {
    pub index: IndexOutcome,
    /// Each stream's outcome, by id. Empty unless the index was accepted.
    pub streams: BTreeMap<String, StreamOutcome>,
    /// Keys a publisher's key set adds without a valid endorsement, waiting
    /// for a person to approve them.
    pub pending_keys: Vec<Pin>,
    /// Problems that failed nothing on their own, such as a key set that
    /// couldn't be fetched or was refused.
    pub fetch_errors: Vec<String>,
    /// The index's ETag, to send next poll. Given only when everything in
    /// this poll was accepted, unchanged or withdrawn, so that a stream that
    /// failed or was refused is tried again rather than skipped as unchanged.
    ///
    /// On `NotModified` it is the ETag the poll sent, so a caller that keeps
    /// `etag` from every report doesn't lose it.
    pub etag: Option<String>,
    /// The accepted index's `updated_at`; `None` unless the index was
    /// accepted. A stateless reader's destination needs it even when nothing
    /// is delivered, to refuse an older index and to mark withdrawn the
    /// streams a newer one no longer lists.
    pub index_updated_at: Option<String>,
    /// Every stream the accepted index lists, in its order; empty unless the
    /// index was accepted.
    pub stream_ids: Vec<String>,
}

/// How to poll.
#[derive(Clone, Debug, Default)]
pub struct PullOptions<'a> {
    /// The reader's age identity, for an encrypted feed.
    pub identity: Option<&'a str>,
    /// The ETag from the last poll's report.
    pub etag: Option<String>,
    /// Limits on each bundle opened.
    pub limits: Limits,
}

/// Decrypts a stored file for `pull`, to at most `max_bytes`. The error is
/// the reason, without the path.
#[cfg(feature = "age")]
fn unseal(bytes: &[u8], identity: Option<&str>, max_bytes: u64) -> Result<Vec<u8>, String> {
    let identity = identity.ok_or("it is encrypted, and no age identity is configured")?;
    crate::age::decrypt(bytes, identity, max_bytes)
}

#[cfg(not(feature = "age"))]
fn unseal(_bytes: &[u8], _identity: Option<&str>, _max_bytes: u64) -> Result<Vec<u8>, String> {
    Err("it is encrypted, and this reader was built without age".to_owned())
}

impl PullReport {
    fn new() -> PullReport {
        PullReport {
            index: IndexOutcome::Accepted,
            streams: BTreeMap::new(),
            pending_keys: Vec::new(),
            fetch_errors: Vec::new(),
            etag: None,
            index_updated_at: None,
            stream_ids: Vec::new(),
        }
    }

    fn index(mut self, outcome: IndexOutcome) -> PullReport {
        self.index = outcome;
        self
    }
}

/// Polls a feed once, following § Reading a feed in order, and delivers each
/// accepted bundle.
///
/// With `state`, the reader keeps state: it refuses a stale index and
/// replayed bundles, skips unchanged streams, notices withdrawn ones, and
/// trusts its connection's pins, its held key sets and the keys a person
/// approved. A refused index changes nothing, and a stream's state changes
/// only once `deliver` returns `Ok`.
///
/// With `state: None`, the reader is stateless: every stream is fetched and
/// checked, `stale_feed` and `replay` aren't checked, and it trusts only the
/// connection's pins, and a key set those pins endorse. Its destination
/// does the history checks with what [`Delivered`] carries.
pub fn pull(
    source: &mut dyn Source,
    keys: &mut dyn KeySource,
    conn: &Connection,
    state: Option<&mut ReaderState>,
    deliver: &mut dyn FnMut(Delivered) -> Result<(), String>,
    options: &PullOptions,
) -> PullReport {
    let mut state = state;
    let mut report = PullReport::new();
    let publisher = conn.publisher().to_owned();

    // 1. Fetch the index, both forms.
    let etag = options.etag.as_deref();
    let plain = match source.get("feed.json", etag) {
        Ok(fetched) => fetched,
        Err(e) => return report.index(IndexOutcome::Failed(format!("feed.json: {e}"))),
    };
    let sealed = match source.get("feed.json.age", etag) {
        Ok(fetched) => fetched,
        Err(e) => return report.index(IndexOutcome::Failed(format!("feed.json.age: {e}"))),
    };
    let (stored, new_etag, encrypted) = match (plain, sealed) {
        (Fetched::NotFound, Fetched::NotFound) => {
            return report.index(IndexOutcome::Failed(
                "neither feed.json nor feed.json.age is there".to_owned(),
            ))
        }
        (Fetched::NotModified, Fetched::NotFound) | (Fetched::NotFound, Fetched::NotModified) => {
            report.etag = options.etag.clone();
            return report.index(IndexOutcome::NotModified);
        }
        (Fetched::Found { bytes, etag }, Fetched::NotFound) => (bytes, etag, false),
        (Fetched::NotFound, Fetched::Found { bytes, etag }) => (bytes, etag, true),
        _ => return report.index(IndexOutcome::Refused(Code::PlainAndEncrypted)),
    };

    // The keys this poll trusts, with the publisher's key set brought up to
    // date first, so that a rotated key can sign the index.
    let mut trust = Trust {
        pins: conn.pins.clone(),
        key_sets: BTreeMap::new(),
        approved: Vec::new(),
    };
    if let Some(state) = state.as_deref() {
        trust.key_sets = state.key_sets.clone();
        trust.approved = state.approved.clone();
    }
    let (new_key_set, serves_key_set) = refresh_key_set(keys, &publisher, &mut trust, &mut report);
    // A publisher that serves a key set must sign its feed and bundles, so
    // one whose key set this poll found counts as pinned for the unsigned
    // rule even before any of its keys is trusted. Otherwise, with no pins
    // and a key set waiting for approval, whoever holds the storage could
    // strip feed.sig and get far-future watermarks accepted.
    let pinned = serves_key_set || trust.trusts_publisher(&publisher);

    // 2. The index's signature, over the stored bytes.
    let sig = match source.get("feed.sig", None) {
        Ok(Fetched::Found { bytes, .. }) => Some(bytes),
        Ok(Fetched::NotFound) => None,
        Ok(Fetched::NotModified) => {
            return report.index(IndexOutcome::Failed(
                "feed.sig: not modified, to a request without an ETag".to_owned(),
            ))
        }
        Err(e) => return report.index(IndexOutcome::Failed(format!("feed.sig: {e}"))),
    };
    if sig.is_none() && pinned {
        return report.index(IndexOutcome::Refused(Code::UnsignedFromPinnedPublisher));
    }
    if let Err(code) = check_signed(
        sig.as_deref(),
        Context::Feed,
        &stored,
        &trust,
        Some(&publisher),
    ) {
        return report.index(IndexOutcome::Refused(code));
    }

    // 3. Decrypt, then the index must be a valid feed whose bundle paths
    // name their own hashes in the feed's mode.
    let stored = if encrypted {
        match unseal(&stored, options.identity, MAX_INDEX_BYTES) {
            Ok(plain) => plain,
            Err(e) => return report.index(IndexOutcome::Failed(format!("feed.json.age: {e}"))),
        }
    } else {
        stored
    };
    let index = match parse_feed(&stored) {
        Ok(index) if check_bundle_paths(&index, encrypted).is_ok() => index,
        _ => return report.index(IndexOutcome::Refused(Code::BadFeed)),
    };

    // 4. It is this connection's feed.
    if index.id != conn.feed || index.publisher != publisher {
        return report.index(IndexOutcome::Refused(Code::WrongFeed));
    }

    // 5. Not older than the last index accepted.
    if let Some(last) = state.as_deref().and_then(|s| s.feed_updated_at.as_deref()) {
        match (time::parse(&index.updated_at), time::parse(last)) {
            (Ok(new), Ok(last)) if new < last => {
                return report.index(IndexOutcome::Refused(Code::StaleFeed))
            }
            (Ok(_), Ok(_)) => {}
            (_, Err(e)) => {
                return report.index(IndexOutcome::Failed(format!(
                    "reader state: feed_updated_at: {e}"
                )))
            }
            // parse_feed checked it.
            (Err(e), _) => return report.index(IndexOutcome::Failed(e)),
        }
    }

    // The index is accepted.
    report.index_updated_at = Some(index.updated_at.clone());
    report.stream_ids = index.streams.iter().map(|s| s.id.clone()).collect();
    if let Some(state) = state.as_deref_mut() {
        state.feed_updated_at = Some(index.updated_at.clone());
        if let Some(set) = new_key_set {
            state.key_sets.insert(set.publisher.clone(), set);
        }
    }

    // 7. Withdrawn: held, and no longer listed.
    if let Some(state) = state.as_deref_mut() {
        let withdrawn: Vec<String> = state
            .streams
            .keys()
            .filter(|id| !index.streams.iter().any(|s| &s.id == *id))
            .cloned()
            .collect();
        for id in withdrawn {
            state.streams.remove(&id);
            report.streams.insert(id, StreamOutcome::Withdrawn);
        }
    }

    // 6, 8–11. Each stream; one failing doesn't stop the others.
    let stream_ids: Vec<String> = index.streams.iter().map(|s| s.id.clone()).collect();
    for entry in &index.streams {
        let held = state.as_deref().and_then(|s| s.streams.get(&entry.id));
        let outcome = match check_stream(source, entry, held, &index, &trust, pinned, options) {
            Err(outcome) => outcome,
            Ok((bundle, signature, published_at)) => {
                let delivered = Delivered {
                    stream: entry.clone(),
                    bundle,
                    signature,
                    published_at: published_at.clone(),
                    feed_updated_at: index.updated_at.clone(),
                    stream_ids: stream_ids.clone(),
                };
                match deliver(delivered) {
                    Ok(()) => {
                        if let Some(state) = state.as_deref_mut() {
                            state.streams.insert(
                                entry.id.clone(),
                                StreamState {
                                    sha256: entry.sha256.clone(),
                                    published_at,
                                },
                            );
                        }
                        StreamOutcome::Accepted
                    }
                    Err(e) => StreamOutcome::Failed(e),
                }
            }
        };
        report.streams.insert(entry.id.clone(), outcome);
    }

    let settled = report.fetch_errors.is_empty()
        && report.streams.values().all(|o| {
            matches!(
                o,
                StreamOutcome::Accepted | StreamOutcome::Unchanged | StreamOutcome::Withdrawn
            )
        });
    if settled {
        report.etag = new_etag;
    }
    report
}

/// Fetches `publisher`'s key set, if the key source has one, and decides
/// about it against the set held in `trust`. An accepted set replaces the
/// held one in `trust`, and is returned for the state to keep once the
/// index is accepted. Anything else keeps the held set: a set that adds
/// keys nobody endorsed or approved puts them in `pending_keys`, and a
/// fetch error or a refused set goes in `fetch_errors`. The flag says
/// whether a key set that parses was served at all.
fn refresh_key_set(
    keys: &mut dyn KeySource,
    publisher: &str,
    trust: &mut Trust,
    report: &mut PullReport,
) -> (Option<KeySet>, bool) {
    let error = |report: &mut PullReport, e: String| {
        report
            .fetch_errors
            .push(format!("key set for {publisher}: {e}"));
    };
    let (bytes, sig) = match keys.key_set(publisher) {
        Ok(Some(fetched)) => fetched,
        Ok(None) => return (None, false),
        Err(e) => {
            error(report, e);
            return (None, false);
        }
    };
    let set = match KeySet::parse(&bytes) {
        Ok(set) => set,
        Err(code) => {
            error(report, code.to_string());
            return (None, false);
        }
    };
    if set.publisher != publisher {
        error(report, format!("it is {}'s key set", set.publisher));
        return (None, true);
    }
    let held = trust.key_sets.get(publisher);
    let pins: Vec<Pin> = trust.pins.iter().chain(&trust.approved).cloned().collect();
    match accept_key_set(held, &pins, &set, sig.as_deref()) {
        Err(code) => {
            error(report, code.to_string());
            return (None, true);
        }
        Ok(KeySetDecision::Accepted) => {}
        Ok(KeySetDecision::NeedsApproval) => {
            // The keys it adds, less those a person already approved: if
            // none is left, the set was approved key by key.
            let is_held = |id: &str, text: &str| match held {
                Some(held) => held
                    .keys
                    .iter()
                    .any(|k| k.id == id && k.public_key_text == text),
                None => pins.iter().any(|p| {
                    p.publisher == publisher
                        && p.id == id
                        && crate::sign::b64url(&p.public_key) == text
                }),
            };
            let added: Vec<_> = set
                .keys
                .iter()
                .filter(|k| !is_held(&k.id, &k.public_key_text))
                .collect();
            if let Some(unknown) = added.iter().find(|k| k.alg != "ed25519") {
                error(
                    report,
                    format!(
                        "it adds key {} with alg {:?}, which this reader can't approve",
                        unknown.id, unknown.alg
                    ),
                );
                return (None, true);
            }
            let pending: Vec<Pin> = added
                .iter()
                .map(|k| Pin {
                    publisher: publisher.to_owned(),
                    id: k.id.clone(),
                    public_key: k.public_key,
                })
                .filter(|pin| !trust.approved.contains(pin))
                .collect();
            if !pending.is_empty() {
                report.pending_keys.extend(pending);
                return (None, true);
            }
        }
    }
    trust.key_sets.insert(publisher.to_owned(), set.clone());
    (Some(set), true)
}

/// Steps 6 and 8–10 for one stream: the bundle, its signature and its
/// manifest's publication fields, or the outcome that stops it.
fn check_stream(
    source: &mut dyn Source,
    entry: &StreamEntry,
    held: Option<&StreamState>,
    index: &Feed,
    trust: &Trust,
    pinned: bool,
    options: &PullOptions,
) -> Result<(Opened, SignatureStatus, String), StreamOutcome> {
    // 6. Unchanged.
    if held.is_some_and(|h| h.sha256 == entry.sha256) {
        return Err(StreamOutcome::Unchanged);
    }
    // 8. Fetch, check the download, check the signature, then the bundle.
    let failed = |e: &str| StreamOutcome::Failed(format!("{}: {e}", entry.bundle));
    let bytes = match source.get(&entry.bundle, None) {
        Ok(Fetched::Found { bytes, .. }) => bytes,
        Ok(Fetched::NotFound) => return Err(failed("not found")),
        Ok(Fetched::NotModified) => {
            return Err(failed("not modified, to a request without an ETag"))
        }
        Err(e) => return Err(failed(&e)),
    };
    if sha256_hex(&bytes) != entry.sha256 {
        return Err(StreamOutcome::Refused(Code::DownloadMismatch));
    }
    // An encrypted feed's bundles are encrypted: the download was checked
    // over the ciphertext, and now it is opened.
    let bytes = if entry.bundle.ends_with(".age") {
        match unseal(&bytes, options.identity, options.limits.max_stored_bytes()) {
            Ok(plain) => plain,
            Err(e) => return Err(failed(&e)),
        }
    } else {
        bytes
    };
    let refused = |code| Err(StreamOutcome::Refused(code));
    let Ok(bundle) = open(&bytes, options.limits) else {
        return refused(Code::BadBundle);
    };
    if bundle.signature.is_none() && pinned {
        return refused(Code::UnsignedFromPinnedPublisher);
    }
    let signature = match check_signature(&bundle, trust, Some(&index.publisher)) {
        Ok(status) => status,
        Err(code) => return refused(code),
    };
    if !verify(&bundle, &[]).problems.is_empty() {
        return refused(Code::BadBundle);
    }
    let manifest_published_at = bundle.manifest.get("published_at");
    let published_at = match &signature {
        SignatureStatus::Verified { .. } => {
            // 9. Where a signed bundle says it belongs.
            let Some(text) = manifest_published_at.and_then(|v| v.as_str()) else {
                return refused(Code::MissingPublishedAt);
            };
            let Ok(instant) = time::parse(text) else {
                return refused(Code::BadBundle);
            };
            let place = bundle.manifest.get("feed");
            let field = |name: &str| place.and_then(|p| p.get(name)).and_then(|v| v.as_str());
            if field("id") != Some(index.id.as_str()) {
                return refused(Code::WrongFeed);
            }
            if field("stream") != Some(entry.id.as_str()) {
                return refused(Code::WrongStream);
            }
            // 10. Later than the last accepted; equal is a replay.
            if let Some(held) = held {
                match time::parse(&held.published_at) {
                    Ok(last) if instant > last => {}
                    Ok(_) => return refused(Code::Replay),
                    Err(e) => return Err(StreamOutcome::Failed(format!("reader state: {e}"))),
                }
            }
            text.to_owned()
        }
        // Unverified: its own date if it gives one, else the index's.
        SignatureStatus::Unverified => manifest_published_at
            .and_then(|v| v.as_str())
            .filter(|text| time::parse(text).is_ok())
            .unwrap_or(&entry.published_at)
            .to_owned(),
    };
    Ok((bundle, signature, published_at))
}
