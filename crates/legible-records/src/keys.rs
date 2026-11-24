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
    /// The key's bytes. Only meaningful when `alg` is `ed25519`; for an
    /// algorithm this reader doesn't know it is all zeros unless the text
    /// happens to be 32 bytes of base64url.
    pub public_key: [u8; 32],
    /// The public key exactly as the set writes it. Keys are compared by this
    /// text, so a key of an unknown algorithm still counts for rollback.
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

    /// Whether this reader may trust the key at all: it ignores a key whose
    /// `alg` it doesn't know.
    fn usable(&self) -> bool {
        self.alg == "ed25519"
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

impl KeySet {
    /// Reads a key set. One that isn't the JSON of its type, or that lists a
    /// key `id` twice, is `bad_key_set`.
    pub fn parse(bytes: &[u8]) -> Result<KeySet, Code> {
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
        let mut keys = Vec::with_capacity(listed.len());
        // Duplicates are refused as the entries are read, before anything
        // looks a key up by id.
        let mut seen = BTreeSet::new();
        for entry in listed {
            let entry = entry.as_object().ok_or(Code::BadKeySet)?;
            let id = text(entry, "id")?;
            if !is_key_id(&id) || !seen.insert(id.clone()) {
                return Err(Code::BadKeySet);
            }
            let alg = text(entry, "alg")?;
            let public_key_text = text(entry, "public_key")?;
            let decoded = from_b64url(&public_key_text)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok());
            let public_key = match decoded {
                Some(key) => key,
                None if alg == "ed25519" => return Err(Code::BadKeySet),
                None => [0; 32],
            };
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

    /// The key with this id.
    pub fn get(&self, id: &str) -> Option<&KeyEntry> {
        self.keys.iter().find(|key| key.id == id)
    }

    fn has_repeated_id(&self) -> bool {
        let mut seen = BTreeSet::new();
        self.keys.iter().any(|key| !seen.insert(key.id.as_str()))
    }
}

/// A key a reader holds from its configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    pub publisher: String,
    pub id: String,
    pub public_key: [u8; 32],
}

/// What a reader does with a key set that broke no rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySetDecision {
    Accepted,
    /// It adds a key with no valid endorsement: a person decides.
    NeedsApproval,
}

/// Whether a key set that adds a key is accepted: without an endorsement it
/// waits for a person, and one that adds none is accepted.
fn unendorsed(adds_key: bool) -> KeySetDecision {
    if adds_key {
        KeySetDecision::NeedsApproval
    } else {
        KeySetDecision::Accepted
    }
}

/// Decides about `new`, served with `sig` (the bytes of `keys.sig`) if it came
/// with one, following § Key sets in order.
///
/// `previous` is the last key set the reader accepted. A reader that keeps
/// nothing between runs passes `None` and its `pins` instead.
pub fn accept_key_set(
    previous: Option<&KeySet>,
    pins: &[Pin],
    new: &KeySet,
    sig: Option<&[u8]>,
) -> Result<KeySetDecision, Code> {
    // 1. Parse: a repeated id is refused before any lookup by id, whichever
    // set it is in.
    if new.has_repeated_id() || previous.is_some_and(KeySet::has_repeated_id) {
        return Err(Code::BadKeySet);
    }
    // What the reader holds, as (id, public key text).
    let held: Vec<(&str, String)> = match previous {
        Some(previous) => {
            // 2. Rollback, before any endorsement is looked at.
            if new.publisher != previous.publisher {
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
                        .any(|k| k.public_key_text == old.public_key_text && k.id != old.id)
                });
            if revived {
                return Err(Code::KeySetRollback);
            }
            previous
                .keys
                .iter()
                .map(|k| (k.id.as_str(), k.public_key_text.clone()))
                .collect()
        }
        None => pins
            .iter()
            .filter(|pin| pin.publisher == new.publisher)
            .map(|pin| (pin.id.as_str(), crate::sign::b64url(&pin.public_key)))
            .collect(),
    };
    // A key is new when the reader holds no key with its id and public key.
    let adds_key = new.keys.iter().any(|k| {
        !held
            .iter()
            .any(|(id, key)| *id == k.id && *key == k.public_key_text)
    });

    let Some(sig) = sig else {
        return Ok(unendorsed(adds_key));
    };
    // Who the signature file says signed, read leniently: a file too broken to
    // name anyone is a bad endorsement.
    let named: Value = serde_json::from_slice(sig).map_err(|_| Code::BadEndorsement)?;
    let (named_publisher, named_key) = match (
        named.get("publisher").and_then(Value::as_str),
        named.get("key").and_then(Value::as_str),
    ) {
        (Some(publisher), Some(key)) => (publisher, key),
        _ => return Err(Code::BadEndorsement),
    };
    if named_publisher != new.publisher {
        return Err(Code::BadEndorsement);
    }
    // The new set may retire the endorsing key but not revoke it.
    let revoked_now = new.get(named_key).is_some_and(|k| k.revoked_at.is_some());
    let endorser: Option<[u8; 32]> = match previous {
        Some(previous) => {
            // 3. Active in the previous set.
            match previous.get(named_key) {
                Some(k) if k.usable() && k.state() == KeyState::Active && !revoked_now => {
                    Some(k.public_key)
                }
                _ => return Err(Code::BadEndorsement),
            }
        }
        None => {
            // Stateless: only a pinned key the new set doesn't revoke counts.
            // Anything else is no endorsement at all, not a bad one.
            pins.iter()
                .find(|pin| pin.publisher == new.publisher && pin.id == named_key)
                .filter(|_| !revoked_now)
                .map(|pin| pin.public_key)
        }
    };
    let Some(endorser) = endorser else {
        return Ok(unendorsed(adds_key));
    };
    let file = SignatureFile::parse(sig).map_err(|_| Code::BadEndorsement)?;
    let key = PublicKey {
        publisher: new.publisher.clone(),
        id: named_key.to_owned(),
        key: endorser,
    };
    verify(&key, Context::Keys, &new.bytes, &file).map_err(|_| Code::BadEndorsement)?;
    // 4. A valid endorsement accepts the set, new keys included.
    Ok(KeySetDecision::Accepted)
}

/// What a reader finds for a publisher and key id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    Found(PublicKey, KeyState),
    Unknown,
}

/// The keys a reader trusts.
#[derive(Clone, Debug, Default)]
pub struct Trust {
    /// Keys from the reader's configuration.
    pub pins: Vec<Pin>,
    /// The last key set accepted for each publisher.
    pub key_sets: BTreeMap<String, KeySet>,
    /// Keys a person approved, trusted like pins.
    pub approved: Vec<Pin>,
}

impl Trust {
    /// The key a publisher's id names. A key set's word on a key outweighs a
    /// pin's, so a pinned key its set revokes is `Revoked`.
    pub fn lookup(&self, publisher: &str, id: &str) -> Lookup {
        let set = self.key_sets.get(publisher);
        if let Some(key) = set.and_then(|set| set.get(id)) {
            if key.usable() {
                return Lookup::Found(
                    PublicKey {
                        publisher: publisher.to_owned(),
                        id: id.to_owned(),
                        key: key.public_key,
                    },
                    key.state(),
                );
            }
            // An unknown algorithm is ignored, and a pin can't stand in for it.
            return Lookup::Unknown;
        }
        let pinned = self
            .pins
            .iter()
            .chain(&self.approved)
            .find(|pin| pin.publisher == publisher && pin.id == id);
        match pinned {
            Some(pin) => {
                // A key the set revokes under another id is revoked too.
                let revoked = set.is_some_and(|set| {
                    set.keys.iter().any(|k| {
                        k.usable()
                            && k.public_key == pin.public_key
                            && k.state() == KeyState::Revoked
                    })
                });
                let state = if revoked {
                    KeyState::Revoked
                } else {
                    KeyState::Active
                };
                Lookup::Found(
                    PublicKey {
                        publisher: pin.publisher.clone(),
                        id: pin.id.clone(),
                        key: pin.public_key,
                    },
                    state,
                )
            }
            None => Lookup::Unknown,
        }
    }

    /// Whether the reader holds a pinned (or approved) key for this publisher.
    pub fn pins_publisher(&self, publisher: &str) -> bool {
        self.pins
            .iter()
            .chain(&self.approved)
            .any(|pin| pin.publisher == publisher)
    }
}
