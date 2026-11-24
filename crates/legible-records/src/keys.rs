//! Key sets (`spec/records.md` § Key sets): parsing, the rules for accepting a
//! new one, and what a reader trusts.

use crate::code::Code;
use crate::sign::{
    from_b64url, is_key_id, is_publisher, verify, Context, PublicKey, SignatureFile,
};
use crate::time::{self, Instant};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The `$type` of a key set.
const KEYS_TYPE: &str = "org.legiblerecords.keys";

/// Where a key is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyState {
    Active,
    /// Ordinary rotation: what it signed still verifies.
    Retired,
    /// Compromised: nothing it signed verifies.
    Revoked,
}

/// One key of a key set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    pub id: String,
    pub alg: String,
    /// The key's 32 bytes, decoded from canonical base64url whatever its
    /// `alg`. Keys are compared by these bytes, never by their text.
    pub public_key: [u8; 32],
    /// The public key exactly as the set writes it.
    pub public_key_text: String,
    pub created_at: String,
    pub retired_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl KeyEntry {
    /// A key with both dates is revoked.
    pub fn state(&self) -> KeyState {
        if self.revoked_at.is_some() {
            KeyState::Revoked
        } else if self.retired_at.is_some() {
            KeyState::Retired
        } else {
            KeyState::Active
        }
    }
}

/// A publisher's key set, with the bytes it was served as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySet {
    pub publisher: String,
    pub updated_at: String,
    pub keys: Vec<KeyEntry>,
    pub bytes: Vec<u8>,
    updated: Instant,
}

fn text(object: &serde_json::Map<String, Value>, name: &str) -> Result<String, Code> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Code::BadKeySet)
}

fn optional_instant(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<String>, Code> {
    match object.get(name) {
        None => Ok(None),
        Some(Value::String(s)) => time::parse(s)
            .map(|_| Some(s.clone()))
            .map_err(|_| Code::BadKeySet),
        Some(_) => Err(Code::BadKeySet),
    }
}

/// How strictly [`KeySet::parse`] reads: as a valid record of its type
/// only, or with every rule of § Key sets step 1.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Strictness {
    Record,
    Rules,
}

fn parse_set(bytes: &[u8], strictness: Strictness) -> Result<KeySet, Code> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Code::BadKeySet)?;
    let object = value.as_object().ok_or(Code::BadKeySet)?;
    if text(object, "$type")? != KEYS_TYPE || object.get("version") != Some(&Value::from(1)) {
        return Err(Code::BadKeySet);
    }
    let publisher = text(object, "publisher")?;
    if !is_publisher(&publisher) {
        return Err(Code::BadKeySet);
    }
    let updated_at = text(object, "updated_at")?;
    let updated = time::parse(&updated_at).map_err(|_| Code::BadKeySet)?;
    let listed = object
        .get("keys")
        .and_then(Value::as_array)
        .filter(|keys| !keys.is_empty())
        .ok_or(Code::BadKeySet)?;
    let strict = strictness == Strictness::Rules;
    let mut keys = Vec::with_capacity(listed.len());
    // Repeats are refused as the entries are read, before anything looks a
    // key up by id or by its bytes.
    let (mut ids, mut publics) = (BTreeSet::new(), BTreeSet::new());
    for entry in listed {
        let entry = entry.as_object().ok_or(Code::BadKeySet)?;
        let id = text(entry, "id")?;
        if !is_key_id(&id) {
            return Err(Code::BadKeySet);
        }
        let alg = text(entry, "alg")?;
        let public_key_text = text(entry, "public_key")?;
        // The schema's pattern: 43 characters of the base64url alphabet.
        let shaped = public_key_text.len() == 43
            && public_key_text
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
        if !shaped {
            return Err(Code::BadKeySet);
        }
        // Canonical: the unused low bits of the last character are zero.
        let decoded = from_b64url(&public_key_text)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok());
        let public_key = match decoded {
            Some(key) => key,
            None if strict => return Err(Code::BadKeySet),
            None => [0; 32],
        };
        if strict && (!ids.insert(id.clone()) || !publics.insert(public_key)) {
            return Err(Code::BadKeySet);
        }
        let created_at = text(entry, "created_at")?;
        time::parse(&created_at).map_err(|_| Code::BadKeySet)?;
        keys.push(KeyEntry {
            id,
            alg,
            public_key,
            public_key_text,
            created_at,
            retired_at: optional_instant(entry, "retired_at")?,
            revoked_at: optional_instant(entry, "revoked_at")?,
        });
    }
    Ok(KeySet {
        publisher,
        updated_at,
        keys,
        bytes: bytes.to_vec(),
        updated,
    })
}

/// How far ahead of the reader's clock a timestamp may be: 24 hours, for
/// clocks that differ.
pub const MAX_SKEW_MILLIS: i64 = 24 * 60 * 60 * 1000;

/// Whether `at` is more than 24 hours after the reader's clock `now`.
pub fn too_far_ahead(at: Instant, now: Instant) -> bool {
    at > now.plus_millis(MAX_SKEW_MILLIS)
}

/// Whether `bytes` are a valid `org.legiblerecords.keys` record, whatever
/// else is wrong with them as a key set. A publisher that serves one shows
/// it signs, so a reader trusts it for the unsigned rule (feeds.md § Trust)
/// even when it refuses the set.
pub fn is_key_set_record(bytes: &[u8]) -> bool {
    parse_set(bytes, Strictness::Record).is_ok()
}

impl KeySet {
    /// Reads a key set (§ Key sets, step 1). One that isn't JSON or isn't a
    /// valid record of its type, lists a key `id` twice, lists one public key
    /// under two ids, or has a `public_key` that isn't canonical base64url of
    /// 32 bytes, is `bad_key_set`. The checks that need the reader's clock
    /// and the domain the set was fetched from are [`KeySet::check_served`].
    pub fn parse(bytes: &[u8]) -> Result<KeySet, Code> {
        parse_set(bytes, Strictness::Rules)
    }

    /// The rest of step 1 for a set as served: its `updated_at` may be no
    /// more than 24 hours after `now`, and its `publisher` must be the
    /// domain it was fetched from, when that is known (`bad_key_set`).
    pub fn check_served(&self, now: Instant, fetched_from: Option<&str>) -> Result<(), Code> {
        if too_far_ahead(self.updated, now) {
            return Err(Code::BadKeySet);
        }
        if fetched_from.is_some_and(|domain| domain != self.publisher) {
            return Err(Code::BadKeySet);
        }
        Ok(())
    }

    /// The key with this id.
    pub fn get(&self, id: &str) -> Option<&KeyEntry> {
        self.keys.iter().find(|key| key.id == id)
    }

    /// Whether this set revokes the key `id`, or the public key `bytes`
    /// under any id.
    pub fn revokes(&self, id: &str, bytes: Option<&[u8; 32]>) -> bool {
        self.keys
            .iter()
            .any(|k| k.revoked_at.is_some() && (k.id == id || Some(&k.public_key) == bytes))
    }

    fn has_repeated_id(&self) -> bool {
        let mut seen = BTreeSet::new();
        self.keys.iter().any(|key| !seen.insert(key.id.as_str()))
    }
}

/// A key a reader holds from its configuration (a pin), or that a person
/// approved: a publisher, a key id, an `alg` and a public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    pub publisher: String,
    pub id: String,
    pub alg: String,
    pub public_key: [u8; 32],
}

/// Reads a pin from its four fields, as a connection file, a reader state's
/// `approved`, the command line and the npm package all give them: a
/// publisher (a lowercase domain), a key id, `alg` `ed25519` (the only one
/// this reader can verify with) and a public key in canonical base64url
/// of 32 bytes. The error says which field is wrong, without echoing the key.
pub fn parse_pin(publisher: &str, id: &str, alg: &str, public_key: &str) -> Result<Pin, String> {
    if !is_publisher(publisher) {
        return Err(format!(
            "publisher {publisher:?} is not a domain: use a lowercase domain such as acme.example, with no scheme, port or path"
        ));
    }
    if !is_key_id(id) {
        return Err(format!(
            "id {id:?} is not a key id: use lowercase letters, digits, dots and hyphens, up to 64, such as 2026-11"
        ));
    }
    if alg != "ed25519" {
        return Err(format!("alg {alg:?} is not ed25519"));
    }
    let public_key = from_b64url(public_key)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or("public_key is not 32 bytes of canonical base64url without padding")?;
    Ok(Pin {
        publisher: publisher.to_owned(),
        id: id.to_owned(),
        alg: alg.to_owned(),
        public_key,
    })
}

/// Reads a pin written `<publisher>/<id>=<public_key>`, as `--pin` and
/// `--approve` take it; its `alg` is `ed25519`.
pub fn parse_pin_text(text: &str) -> Result<Pin, String> {
    let shape = "expected <publisher>/<id>=<public_key>, such as acme.example/2026-11=<base64url>";
    let (name, key) = text.split_once('=').ok_or(shape)?;
    let (publisher, id) = name.split_once('/').ok_or(shape)?;
    parse_pin(publisher, id, "ed25519", key).map_err(|e| format!("{e}; {shape}"))
}

/// What a reader does with a key set that broke no rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySetDecision {
    Accepted,
    /// It adds a key with no valid endorsement: a person decides.
    NeedsApproval,
}

/// Every `(alg, public key)` the reader's anchors give for `publisher`'s key
/// `id`: its pins and approved keys (`anchors`), and the held set's entry.
fn sources(
    held: Option<&KeySet>,
    anchors: &[Pin],
    publisher: &str,
    id: &str,
) -> Vec<(String, [u8; 32])> {
    let mut found: Vec<(String, [u8; 32])> = Vec::new();
    let from_anchors = anchors
        .iter()
        .filter(|a| a.publisher == publisher && a.id == id)
        .map(|a| (a.alg.clone(), a.public_key));
    let from_held = held
        .filter(|set| set.publisher == publisher)
        .and_then(|set| set.get(id))
        .map(|k| (k.alg.clone(), k.public_key));
    for source in from_anchors.chain(from_held) {
        if !found.contains(&source) {
            found.push(source);
        }
    }
    found
}

/// The keys `new` adds: those no anchor has with the same id, `alg` and
/// public key. A key whose public key or `alg` changed under a held id is
/// new. `anchors` are the reader's pins and approved keys; `previous` the
/// set it holds.
pub fn new_keys<'a>(
    previous: Option<&KeySet>,
    anchors: &[Pin],
    new: &'a KeySet,
) -> Vec<&'a KeyEntry> {
    new.keys
        .iter()
        .filter(|k| {
            !sources(previous, anchors, &new.publisher, &k.id)
                .contains(&(k.alg.clone(), k.public_key))
        })
        .collect()
}

/// Who a `keys.sig` names, if it is the signature file of § Signed bundles:
/// JSON with the four string members, `alg` `ed25519` and a canonical
/// 64-byte signature. Every failure is `bad_endorsement`.
fn endorsement_file(sig: &[u8]) -> Result<SignatureFile, Code> {
    SignatureFile::parse(sig).map_err(|_| Code::BadEndorsement)
}

/// Decides about `new`, served with `sig` (the bytes of `keys.sig`) if it
/// came with one, following § Key sets in order: rollback, then
/// endorsement, then whether it adds a key.
///
/// `previous` is the last key set the reader accepted, or `None`; `anchors`
/// are its pinned and approved keys (a stateless reader passes its pins and
/// `None`). A `keys.sig` by a key that is no anchor, an alias, or one the anchors
/// disagree about, is no endorsement rather than a bad one.
///
/// Step 1's checks that need the reader's clock or where the set came from
/// are [`KeySet::check_served`]; [`decide_key_set`] runs them all.
pub fn accept_key_set(
    previous: Option<&KeySet>,
    anchors: &[Pin],
    new: &KeySet,
    sig: Option<&[u8]>,
) -> Result<KeySetDecision, Code> {
    // 1. Parse: a repeated id is refused before any lookup by id, whichever
    // set it is in.
    if new.has_repeated_id() || previous.is_some_and(KeySet::has_repeated_id) {
        return Err(Code::BadKeySet);
    }
    let publisher = new.publisher.as_str();
    // 2. Rollback, before any endorsement is looked at.
    if let Some(previous) = previous {
        if previous.publisher != publisher {
            return Err(Code::BadEndorsement);
        }
        if new.updated < previous.updated {
            return Err(Code::KeySetRollback);
        }
        for old in &previous.keys {
            let now = new.get(&old.id).ok_or(Code::KeySetRollback)?;
            if (old.retired_at.is_some() && now.retired_at.is_none())
                || (old.revoked_at.is_some() && now.revoked_at.is_none())
            {
                return Err(Code::KeySetRollback);
            }
        }
        // A compromised key can't come back under a fresh id.
        let revived = previous
            .keys
            .iter()
            .filter(|old| old.revoked_at.is_some())
            .any(|old| {
                new.keys
                    .iter()
                    .any(|k| k.public_key == old.public_key && k.id != old.id)
            });
        if revived {
            return Err(Code::KeySetRollback);
        }
    }
    let held = previous;
    let adds_key = !new_keys(held, anchors, new).is_empty();
    let unendorsed = if adds_key {
        KeySetDecision::NeedsApproval
    } else {
        KeySetDecision::Accepted
    };
    let Some(sig) = sig else {
        return Ok(unendorsed);
    };
    // 3. Endorsement: every failure is bad_endorsement.
    let file = endorsement_file(sig)?;
    if file.publisher != publisher {
        return Err(Code::BadEndorsement);
    }
    let found = sources(held, anchors, publisher, &file.key);
    let [(alg, endorser)] = found.as_slice() else {
        // No anchor, or anchors that disagree: no endorsement.
        return Ok(unendorsed);
    };
    // An anchor that may not endorse: retired or revoked in the held set,
    // revoked (by id or bytes) there, or revoked by the new set itself.
    if held
        .and_then(|set| set.get(&file.key))
        .is_some_and(|k| k.retired_at.is_some() || k.revoked_at.is_some())
    {
        return Err(Code::BadEndorsement);
    }
    if held.is_some_and(|set| set.revokes(&file.key, Some(endorser))) {
        return Err(Code::BadEndorsement);
    }
    if new.revokes(&file.key, Some(endorser)) {
        return Err(Code::BadEndorsement);
    }
    // An anchor whose public key the held set or this new set lists under
    // another id is no anchor (one key, one name): no endorsement.
    let aliased = |set: &KeySet| {
        set.keys
            .iter()
            .any(|k| k.id != file.key && &k.public_key == endorser)
    };
    if held.is_some_and(aliased) || aliased(new) {
        return Ok(unendorsed);
    }
    if alg != "ed25519" {
        return Err(Code::BadEndorsement);
    }
    let key = PublicKey {
        publisher: publisher.to_owned(),
        id: file.key.clone(),
        key: *endorser,
    };
    verify(&key, Context::Keys, &new.bytes, &file).map_err(|_| Code::BadEndorsement)?;
    // 4. A valid endorsement accepts the set, new keys included.
    Ok(KeySetDecision::Accepted)
}

/// What a reader decided about a key set as served.
#[derive(Clone, Debug)]
pub struct KeySetVerdict {
    /// The decision, or the code the set is refused with.
    pub outcome: Result<KeySetDecision, Code>,
    /// The set, when it passed § Key sets step 1 (it parses, isn't too far
    /// ahead of the reader's clock, and names the domain it came from). Its
    /// revocations count whatever the outcome; it is held only if accepted.
    pub set: Option<KeySet>,
    /// The keys it adds without a valid endorsement, when it waits for
    /// approval.
    pub pending: Vec<Pin>,
}

/// Decides about a key set as served (`keys_json` and, if there is one,
/// `keys_sig`), running every step of § Key sets: step 1 with the reader's
/// clock `now` and the domain the set was `fetched_from` (when known), then
/// [`accept_key_set`] against the held set `previous` and the reader's
/// pinned and approved keys `anchors`.
pub fn decide_key_set(
    previous: Option<&KeySet>,
    anchors: &[Pin],
    keys_json: &[u8],
    keys_sig: Option<&[u8]>,
    now: Instant,
    fetched_from: Option<&str>,
) -> KeySetVerdict {
    let refused = |code| KeySetVerdict {
        outcome: Err(code),
        set: None,
        pending: Vec::new(),
    };
    let set = match KeySet::parse(keys_json) {
        Ok(set) => set,
        Err(code) => return refused(code),
    };
    if let Err(code) = set.check_served(now, fetched_from) {
        return refused(code);
    }
    let outcome = accept_key_set(previous, anchors, &set, keys_sig);
    let pending = match outcome {
        Ok(KeySetDecision::NeedsApproval) => new_keys(previous, anchors, &set)
            .into_iter()
            .map(|k| Pin {
                publisher: set.publisher.clone(),
                id: k.id.clone(),
                alg: k.alg.clone(),
                public_key: k.public_key,
            })
            .collect(),
        _ => Vec::new(),
    };
    KeySetVerdict {
        outcome,
        set: Some(set),
        pending,
    }
}

/// What a reader finds for a publisher and key id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    Found(PublicKey, KeyState),
    /// The key's `alg` isn't one this reader knows: `unknown_alg`.
    UnknownAlg,
    /// No trusted key has that id, or the reader's sources disagree about
    /// it: `unknown_key`.
    Unknown,
}

/// A key a key set marks revoked, as a poll reports it to a stateless
/// reader's destination (feeds.md § Trust).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revocation {
    pub publisher: String,
    /// The key's id in the set that revokes it.
    pub id: String,
    /// Its public key: a signer recorded under another id with these bytes
    /// is revoked too. A stateless reader's destination matches a revocation
    /// to the signers it holds by publisher and these bytes, not by id.
    pub public_key: [u8; 32],
    pub revoked_at: String,
    /// Whether the set that revokes it is held (one accepted on this poll
    /// included). Only a held revocation clears what the key signed; one
    /// from a set the reader doesn't hold (waiting for approval, or refused
    /// as `bad_endorsement` or `key_set_rollback`) refuses what the key
    /// signed on this poll and changes nothing the destination keeps.
    pub held: bool,
}

/// The keys a reader trusts (feeds.md § Trust).
#[derive(Clone, Debug, Default)]
pub struct Trust {
    /// Keys from the reader's configuration.
    pub pins: Vec<Pin>,
    /// The key set held for each publisher: the last one accepted,
    /// including one accepted on this poll.
    pub key_sets: BTreeMap<String, KeySet>,
    /// Keys a person approved, trusted like pins.
    pub approved: Vec<Pin>,
    /// Key sets served on this poll that aren't held (waiting for approval,
    /// or refused after step 1). Their revocations refuse signatures on this
    /// poll, in [`Trust::lookup`], and do nothing else: they never clear
    /// what a key signed ([`Trust::held_revokes`]).
    pub revoking: Vec<KeySet>,
    /// Publishers that served a valid key set record on this poll, whatever
    /// became of it: a reader trusts them for the unsigned rule.
    pub served: BTreeSet<String>,
}

impl Trust {
    fn anchors(&self) -> Vec<Pin> {
        self.pins.iter().chain(&self.approved).cloned().collect()
    }

    /// Whether a held or revoking set for `publisher` revokes the key `id`,
    /// or the public key `bytes` under any id.
    fn revokes(&self, publisher: &str, id: &str, bytes: Option<&[u8; 32]>) -> bool {
        self.key_sets
            .get(publisher)
            .into_iter()
            .chain(self.revoking.iter().filter(|s| s.publisher == publisher))
            .any(|set| set.revokes(id, bytes))
    }

    /// Whether `id` is pinned or approved for `publisher` and a held or
    /// revoking set for it lists the public key `bytes` under another id.
    fn aliased(&self, publisher: &str, id: &str, bytes: &[u8; 32]) -> bool {
        let anchored = self
            .pins
            .iter()
            .chain(&self.approved)
            .any(|a| a.publisher == publisher && a.id == id);
        anchored
            && self
                .key_sets
                .get(publisher)
                .into_iter()
                .chain(self.revoking.iter().filter(|s| s.publisher == publisher))
                .flat_map(|set| &set.keys)
                .any(|k| k.id != id && &k.public_key == bytes)
    }

    /// The key a publisher's id names, as § Trust defines it: the held set's
    /// entry, a pin and an approved key must agree on its `alg` and bytes,
    /// or the id names no trusted key; a key a held or revoking set revokes,
    /// by id or by its bytes under another id, is `Revoked` even if pinned;
    /// a pinned or approved key whose bytes a held or revoking set lists
    /// under another id names no trusted key (one key, one name: the pin is
    /// out of date or wrong); a key whose `alg` this reader doesn't know is
    /// `UnknownAlg`.
    pub fn lookup(&self, publisher: &str, id: &str) -> Lookup {
        let held = self.key_sets.get(publisher);
        let found = sources(held, &self.anchors(), publisher, id);
        let [(alg, key)] = found.as_slice() else {
            return Lookup::Unknown;
        };
        let public = PublicKey {
            publisher: publisher.to_owned(),
            id: id.to_owned(),
            key: *key,
        };
        if self.revokes(publisher, id, Some(key)) {
            return Lookup::Found(public, KeyState::Revoked);
        }
        if self.aliased(publisher, id, key) {
            return Lookup::Unknown;
        }
        if alg != "ed25519" {
            return Lookup::UnknownAlg;
        }
        let state = held
            .and_then(|set| set.get(id))
            .map_or(KeyState::Active, KeyEntry::state);
        Lookup::Found(public, state)
    }

    /// Whether the key `publisher` / `id`, which signed something the reader
    /// accepted before, has been revoked since by the held set: by id, or by
    /// its bytes under another id. Only this clears what a key signed; a
    /// revoking set that isn't held never does (feeds.md § Trust), since
    /// anyone who controls the server can serve one with no key.
    pub fn held_revokes(&self, publisher: &str, id: &str) -> bool {
        let Some(held) = self.key_sets.get(publisher) else {
            return false;
        };
        let found = sources(Some(held), &self.anchors(), publisher, id);
        if found.is_empty() {
            return held.revokes(id, None);
        }
        found.iter().any(|(_, key)| held.revokes(id, Some(key)))
    }

    /// Every key the held set or a revoking set for `publisher` revokes,
    /// marked by whether its set is held. A key both revoke is listed once,
    /// as held.
    pub fn revocations(&self, publisher: &str) -> Vec<Revocation> {
        let mut found: Vec<Revocation> = Vec::new();
        let held = self.key_sets.get(publisher).into_iter().map(|s| (s, true));
        let unheld = self
            .revoking
            .iter()
            .filter(|s| s.publisher == publisher)
            .map(|s| (s, false));
        for (set, is_held) in held.chain(unheld) {
            for key in &set.keys {
                let Some(revoked_at) = &key.revoked_at else {
                    continue;
                };
                if found
                    .iter()
                    .any(|r| r.id == key.id && r.public_key == key.public_key)
                {
                    continue;
                }
                found.push(Revocation {
                    publisher: set.publisher.clone(),
                    id: key.id.clone(),
                    public_key: key.public_key,
                    revoked_at: revoked_at.clone(),
                    held: is_held,
                });
            }
        }
        found
    }

    /// Whether the reader holds a pinned (or approved) key for this publisher.
    pub fn pins_publisher(&self, publisher: &str) -> bool {
        self.pins
            .iter()
            .chain(&self.approved)
            .any(|pin| pin.publisher == publisher)
    }

    /// Whether the reader trusts this publisher (§ Trust): it has a pinned
    /// or approved key for it, holds its key set, or was served a valid key
    /// set record by it on this poll. A reader that does refuses this
    /// publisher's unsigned bundles and feed indexes.
    pub fn trusts_publisher(&self, publisher: &str) -> bool {
        self.pins_publisher(publisher)
            || self.key_sets.contains_key(publisher)
            || self.served.contains(publisher)
    }
}
