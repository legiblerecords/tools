//! Reading a feed (`spec/feeds.md` § Reading a feed, § Reader state): one
//! poll, over a [`Source`] and a [`KeySource`], with no I/O of its own.

use std::collections::BTreeMap;

use super::connection::Connection;
use super::index::{check_bundle_paths, parse_feed, Feed, StreamEntry};
use super::source::{Fetched, KeySource, Source};
use super::state::{ReaderState, Signer, StreamState};
use super::MAX_INDEX_BYTES;
use crate::bundle::{
    check_signature, check_signed, open, sha256_hex, verify_at, Limits, Opened, SignatureStatus,
};
use crate::code::Code;
use crate::keys::{
    decide_key_set, is_key_set_record, too_far_ahead, KeySetDecision, Pin, Revocation, Trust,
};
use crate::sign::Context;
use crate::time::{self, Instant};

/// A bundle `pull` accepted, for its destination.
///
/// A stateless reader's destination does the history checks itself, so each
/// delivery carries what they need: the bundle's `published_at`, `sha256`
/// (in `stream`) and signer with its public key (`signature`), the index's
/// `updated_at` and stream ids, and the poll's `revocations`, each with the
/// revoked key's public key. The destination refuses an
/// index older than the last it accepted and marks nothing withdrawn from
/// it, ignores an unchanged hash, refuses a bundle older than the one it
/// holds or as old with a different hash (a replay), and marks withdrawn the
/// streams a newer index no longer lists. For a revocation marked `held`,
/// it clears what that key signed, matching signers by publisher and public
/// key rather than by id, as a reader with state does, keeping the
/// `published_at` and `updated_at` it holds as floors; for one not held, it
/// changes nothing.
#[derive(Clone, Debug)]
pub struct Delivered {
    /// The stream's entry in the index.
    pub stream: StreamEntry,
    pub bundle: Opened,
    /// The bundle's zip exactly as stored, after decryption if the feed is
    /// encrypted: what a reader that keeps the file writes.
    pub zip: Vec<u8>,
    /// Its signer (`Verified { publisher, key, public_key }`), or
    /// `Unverified`. A destination matches a revocation to it by publisher
    /// and public key, not by id (feeds.md § Trust).
    pub signature: SignatureStatus,
    /// The bundle's `published_at`, as its manifest writes it: the same
    /// instant as the index entry's, which `pull` checks.
    pub published_at: String,
    /// The index's `updated_at`.
    pub feed_updated_at: String,
    /// Every stream the index lists, in its order.
    pub stream_ids: Vec<String>,
    /// The keys revoked on this poll, as [`PullReport::revocations`].
    pub revocations: Vec<Revocation>,
}

/// What became of one stream in a poll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamOutcome {
    /// Checked and delivered; it is now the stream's current bundle.
    Accepted,
    /// Its `sha256` is the last one accepted, so it wasn't fetched.
    Unchanged,
    /// In the reader's state and not in this index.
    Withdrawn,
    /// Refused with an outcome code. `revoked_key` before the index is
    /// checked means the held key set revoked the key that signed the
    /// stream's last accepted bundle: the reader cleared the stream's
    /// `sha256` and signer, kept its `published_at` as a replay floor, and
    /// fetches and checks it anew on the next poll.
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
    /// Refused with an outcome code. Nothing changed but what the key set
    /// steps change (a key set accepted, streams a revoked key signed
    /// cleared).
    Refused(Code),
    /// Couldn't be fetched or read, or the publisher's key set couldn't be
    /// fetched and nothing else says whether it signs. Nothing changed but
    /// what the key set steps change.
    Failed(String),
}

/// What became of the publisher's key set in a poll (§ Trust).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySetOutcome {
    /// The publisher serves no key set (404).
    NotServed,
    /// Accepted, and held from now on.
    Accepted,
    /// It adds these keys without a valid endorsement: they wait for a
    /// person to approve them (`needs_approval`). Its revocations refuse
    /// what the key signed on this poll, and change no state.
    Pending(Vec<Pin>),
    /// Refused with an outcome code (`bad_key_set`, `key_set_rollback` or
    /// `bad_endorsement`). The keys the reader trusts are as they were,
    /// except that a set that passed step 1 still has its revocations
    /// honoured on this poll, without changing any state.
    Refused(Code),
    /// Couldn't be fetched (a failure other than 404). The keys the reader
    /// trusts are as they were.
    Failed(String),
}

/// What a poll found.
#[derive(Clone, Debug)]
pub struct PullReport {
    pub index: IndexOutcome,
    /// Why the index was refused, when there is more to say than its code
    /// (such as what made it `bad_feed`).
    pub index_detail: Option<String>,
    /// What became of the publisher's key set; fetched on every poll.
    pub key_set: KeySetOutcome,
    /// Each stream's outcome, by id: every stream the index lists and every
    /// one withdrawn, once the index is accepted; and, whatever happens to
    /// the index, each stream cleared because the held key set revoked its
    /// signer (`revoked_key`).
    pub streams: BTreeMap<String, StreamOutcome>,
    /// The index's ETag, to send next poll. Given only when everything in
    /// this poll was accepted, unchanged or withdrawn, so that a stream that
    /// failed or was refused (or cleared) is tried again rather than
    /// skipped as unchanged.
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
    /// Every key the feed publisher's key sets revoke on this poll, whatever
    /// happens to the index: the held set's (one accepted on this poll
    /// included), marked `held`, and those of a served set the reader
    /// doesn't hold, which are not. A stateless reader's destination clears
    /// what a held revocation's key signed, and nothing for the others.
    pub revocations: Vec<Revocation>,
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
    /// The reader's clock, for refusing a timestamp more than 24 hours
    /// ahead of it. `None` reads the system clock, which
    /// `wasm32-unknown-unknown` doesn't have: there, pass the host's time.
    pub now: Option<Instant>,
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
            index_detail: None,
            key_set: KeySetOutcome::NotServed,
            streams: BTreeMap::new(),
            etag: None,
            index_updated_at: None,
            stream_ids: Vec::new(),
            revocations: Vec::new(),
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
/// First the keys, on every poll whatever happens to the index: the
/// publisher's key set is fetched and decided on (§ Trust); an accepted one
/// is held from then on, and the revocations of any served set that passed
/// § Key sets step 1 refuse what the key signed on this poll, whatever its
/// endorsement. A reader with state then clears what a key the held set
/// revokes signed: each stream whose last accepted bundle it signed loses
/// its `sha256` and signer, keeps its `published_at` as a replay floor, and
/// is reported `revoked_key`; the index loses its signer and keeps its
/// `updated_at`. A revocation in a set the reader doesn't hold clears
/// nothing, since anyone who controls the server can serve one with no key.
/// A key set that can't be fetched
/// leaves the keys as they were, unless nothing else (a pin, an approved
/// key, a held set) says whether the publisher signs: then the poll fails.
///
/// With `state`, the reader keeps state: it refuses a stale index and
/// replayed bundles, skips unchanged streams, notices withdrawn ones, and
/// trusts its connection's pins, its held key sets and the keys a person
/// approved. A refused index changes nothing else, and a stream's state
/// changes only once `deliver` returns `Ok`.
///
/// With `state: None`, the reader is stateless: every stream is fetched and
/// checked, `stale_feed` and `replay` aren't checked, and its anchors are
/// the connection's pins. Its destination does the history checks with
/// what [`Delivered`] carries.
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
    let now = options.now.unwrap_or_else(time::now);

    // Keys, step 1: the publisher's key set, decided with the held set and
    // the reader's anchors.
    let mut trust = Trust {
        pins: conn.pins.clone(),
        ..Trust::default()
    };
    if let Some(state) = state.as_deref() {
        trust.key_sets = state.key_sets.clone();
        trust.approved = state.approved.clone();
    }
    match keys.key_set(&publisher) {
        Ok(None) => report.key_set = KeySetOutcome::NotServed,
        Err(e) => {
            let e = format!("key set for {publisher}: {e}");
            report.key_set = KeySetOutcome::Failed(e.clone());
            // A failure other than 404 can't make a signing publisher look
            // like one with no key set: without another anchor, stop.
            if !trust.trusts_publisher(&publisher) {
                return report.index(IndexOutcome::Failed(format!(
                    "{e}; nothing else says whether {publisher} signs its feed, so it isn't read"
                )));
            }
        }
        Ok(Some((bytes, sig))) => {
            if is_key_set_record(&bytes) {
                trust.served.insert(publisher.clone());
            }
            let anchors: Vec<Pin> = trust.pins.iter().chain(&trust.approved).cloned().collect();
            let verdict = decide_key_set(
                trust.key_sets.get(&publisher),
                &anchors,
                &bytes,
                sig.as_deref(),
                now,
                Some(&publisher),
            );
            report.key_set = match verdict.outcome {
                Ok(KeySetDecision::Accepted) => KeySetOutcome::Accepted,
                Ok(KeySetDecision::NeedsApproval) => KeySetOutcome::Pending(verdict.pending),
                Err(code) => KeySetOutcome::Refused(code),
            };
            if let Some(set) = verdict.set {
                if report.key_set == KeySetOutcome::Accepted {
                    if let Some(state) = state.as_deref_mut() {
                        state.key_sets.insert(publisher.clone(), set.clone());
                    }
                    trust.key_sets.insert(publisher.clone(), set);
                } else {
                    // Revocation only reduces trust: it counts whatever
                    // became of the set.
                    trust.revoking.push(set);
                }
            }
        }
    }

    report.revocations = trust.revocations(&publisher);

    // Keys, step 2: clear what a key the held set revokes signed. The floors
    // (a stream's published_at, the index's updated_at) stay.
    let mut cleared = false;
    if let Some(state) = state.as_deref_mut() {
        let revoked = |signer: &Option<Signer>| {
            signer
                .as_ref()
                .is_some_and(|s| trust.held_revokes(&s.publisher, &s.key))
        };
        for (id, held) in state.streams.iter_mut() {
            if revoked(&held.signer) {
                held.sha256 = None;
                held.signer = None;
                report
                    .streams
                    .insert(id.clone(), StreamOutcome::Refused(Code::RevokedKey));
                cleared = true;
            }
        }
        if revoked(&state.feed_signer) {
            state.feed_signer = None;
            cleared = true;
        }
    }

    // 3. Fetch the index, both forms. After clearing anything, the index is
    // fetched whole.
    let etag = if cleared {
        None
    } else {
        options.etag.as_deref()
    };
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
            report.etag = etag.map(str::to_owned);
            return report.index(IndexOutcome::NotModified);
        }
        (Fetched::Found { bytes, etag }, Fetched::NotFound) => (bytes, etag, false),
        (Fetched::NotFound, Fetched::Found { bytes, etag }) => (bytes, etag, true),
        _ => return report.index(IndexOutcome::Refused(Code::PlainAndEncrypted)),
    };

    // 4. The index's signature, over the stored bytes. Unsigned from a
    // trusted publisher is refused.
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
    let index_signer = match check_signed(
        sig.as_deref(),
        Context::Feed,
        &stored,
        &trust,
        Some(&publisher),
    ) {
        Ok(status) => signer_of(&status),
        Err(code) => return report.index(IndexOutcome::Refused(code)),
    };

    // 5. Decrypt, then the index must be a valid feed whose bundle paths
    // name their own hashes in the feed's mode, dated no more than 24 hours
    // ahead of the reader's clock.
    let stored = if encrypted {
        match unseal(&stored, options.identity, MAX_INDEX_BYTES) {
            Ok(plain) => plain,
            Err(e) => return report.index(IndexOutcome::Failed(format!("feed.json.age: {e}"))),
        }
    } else {
        stored
    };
    let checked = parse_feed(&stored).and_then(|index| {
        check_bundle_paths(&index, encrypted)?;
        match time::parse(&index.updated_at) {
            Ok(at) if too_far_ahead(at, now) => Err(format!(
                "feed index: updated_at {} is more than 24 hours after this reader's clock",
                index.updated_at
            )),
            _ => Ok(index),
        }
    });
    let index = match checked {
        Ok(index) => index,
        Err(detail) => {
            report.index_detail = Some(detail);
            return report.index(IndexOutcome::Refused(Code::BadFeed));
        }
    };

    // 6. It is this connection's feed.
    if index.id != conn.feed || index.publisher != publisher {
        return report.index(IndexOutcome::Refused(Code::WrongFeed));
    }

    // 7. Not older than the last index accepted.
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
        state.feed_signer = index_signer;
    }

    // 9. Withdrawn: in the state, and not listed. A stream cleared in step 2
    // isn't decided again on this poll.
    if let Some(state) = state.as_deref_mut() {
        let withdrawn: Vec<String> = state
            .streams
            .keys()
            .filter(|id| !index.streams.iter().any(|s| &s.id == *id))
            .filter(|id| !report.streams.contains_key(*id))
            .cloned()
            .collect();
        for id in withdrawn {
            state.streams.remove(&id);
            report.streams.insert(id, StreamOutcome::Withdrawn);
        }
    }

    // 8, 10–13. Each stream; one failing doesn't stop the others. A stream
    // cleared in step 2 isn't checked again on this poll.
    let stream_ids: Vec<String> = index.streams.iter().map(|s| s.id.clone()).collect();
    for entry in &index.streams {
        if report.streams.contains_key(&entry.id) {
            continue;
        }
        let held = state.as_deref().and_then(|s| s.streams.get(&entry.id));
        let outcome = match check_stream(source, entry, held, &index, &trust, now, options) {
            Err(outcome) => outcome,
            Ok((bundle, zip, signature, published_at)) => {
                let signer = signer_of(&signature);
                let delivered = Delivered {
                    stream: entry.clone(),
                    bundle,
                    zip,
                    signature,
                    published_at: published_at.clone(),
                    feed_updated_at: index.updated_at.clone(),
                    stream_ids: stream_ids.clone(),
                    revocations: report.revocations.clone(),
                };
                match deliver(delivered) {
                    Ok(()) => {
                        if let Some(state) = state.as_deref_mut() {
                            state.streams.insert(
                                entry.id.clone(),
                                StreamState {
                                    sha256: Some(entry.sha256.clone()),
                                    published_at,
                                    signer,
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

    let settled = !cleared
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

/// The signer a reader records: who signed, or `None` for unsigned.
fn signer_of(status: &SignatureStatus) -> Option<Signer> {
    match status {
        SignatureStatus::Verified { publisher, key, .. } => Some(Signer {
            publisher: publisher.clone(),
            key: key.clone(),
        }),
        SignatureStatus::Unverified => None,
    }
}

/// A stream's checked bundle: opened, as stored, its signature status and `published_at`.
type Checked = (Opened, Vec<u8>, SignatureStatus, String);

/// Steps 8 and 10–12 for one stream: the bundle, its signature and its
/// manifest's publication fields, or the outcome that stops it.
fn check_stream(
    source: &mut dyn Source,
    entry: &StreamEntry,
    held: Option<&StreamState>,
    index: &Feed,
    trust: &Trust,
    now: Instant,
    options: &PullOptions,
) -> Result<Checked, StreamOutcome> {
    // 8. Unchanged. A stream a revocation cleared has no sha256 to match.
    if held.is_some_and(|h| h.sha256.as_deref() == Some(entry.sha256.as_str())) {
        return Err(StreamOutcome::Unchanged);
    }
    // 10. Fetch, check the download, read the zip's entry names, check the
    // signature, then the bundle.
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
    // Unsigned from a trusted publisher is refused here too.
    let signature = match check_signature(&bundle, trust, Some(&index.publisher)) {
        Ok(status) => status,
        Err(code) => return refused(code),
    };
    if !verify_at(&bundle, &[], now).problems.is_empty() {
        return refused(Code::BadBundle);
    }
    // 11. Every bundle in a feed has published_at, the index entry's.
    let Some(text) = bundle.manifest.get("published_at").and_then(|v| v.as_str()) else {
        return refused(Code::MissingPublishedAt);
    };
    let (Ok(instant), Ok(listed)) = (time::parse(text), time::parse(&entry.published_at)) else {
        return refused(Code::BadBundle);
    };
    if instant != listed {
        return refused(Code::BadBundle);
    }
    if let SignatureStatus::Verified { .. } = &signature {
        // Where a signed bundle says it belongs.
        let place = bundle.manifest.get("feed");
        let field = |name: &str| place.and_then(|p| p.get(name)).and_then(|v| v.as_str());
        if field("id") != Some(index.id.as_str()) {
            return refused(Code::WrongFeed);
        }
        if field("stream") != Some(entry.id.as_str()) {
            return refused(Code::WrongStream);
        }
        // 12. Later than the last accepted, which a revocation that cleared
        // the stream keeps; equal is a replay.
        if let Some(held) = held {
            match time::parse(&held.published_at) {
                Ok(last) if instant > last => {}
                Ok(_) => return refused(Code::Replay),
                Err(e) => return Err(StreamOutcome::Failed(format!("reader state: {e}"))),
            }
        }
    }
    let published_at = text.to_owned();
    Ok((bundle, bytes, signature, published_at))
}
