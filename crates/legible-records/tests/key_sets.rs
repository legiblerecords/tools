//! Key set vectors and trust.

use legible_records::code::Code;
use legible_records::keys::{accept_key_set, KeySet, KeySetDecision, KeyState, Lookup, Pin, Trust};
use legible_records::sign::{b64url, from_b64url};
use serde_json::Value;

fn pins(value: &Value) -> Vec<Pin> {
    value
        .as_array()
        .expect("pins")
        .iter()
        .map(|p| Pin {
            publisher: p["publisher"].as_str().unwrap().to_owned(),
            id: p["id"].as_str().unwrap().to_owned(),
            public_key: from_b64url(p["public_key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        })
        .collect()
}

fn outcome(result: Result<KeySetDecision, Code>) -> &'static str {
    match result {
        Ok(KeySetDecision::Accepted) => "accepted",
        Ok(KeySetDecision::NeedsApproval) => "needs_approval",
        Err(code) => code.as_str(),
    }
}

/// Vectors this reader doesn't pass yet; each must still fail, so the list
/// only shrinks.
const PENDING: &[&str] = &[
    "alg-changed-unsigned",
    "failures",
    "pin-conflicts-with-held-set",
    "pinned-endorser-with-held-set",
    "same-key-two-ids",
    "stateless-revokes-own-endorser",
    "unheld-endorser-new-key",
    "unheld-endorser-no-new-key",
    "updated-at-future",
    "updated-at-future-of-now",
];

#[test]
fn key_set_vectors() {
    let dir = format!("{}/tests/vectors/key-sets", env!("CARGO_MANIFEST_DIR"));
    let (mut count, mut failures) = (0, Vec::new());
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let case: Value =
            serde_json::from_slice(&std::fs::read(path.join("case.json")).unwrap()).unwrap();
        let name = case["name"].as_str().unwrap();
        let keys_bytes = std::fs::read(path.join("keys.json")).unwrap();
        let sig = std::fs::read(path.join("keys.sig")).ok();
        // A previous set that doesn't parse is a bad key set, as for a new one.
        let got = match KeySet::parse(&keys_bytes) {
            Err(code) => code.as_str(),
            Ok(new) => {
                let previous = if case["previous"].is_null() {
                    Ok(None)
                } else {
                    let bytes = serde_json::to_vec(&case["previous"]).unwrap();
                    KeySet::parse(&bytes).map(Some)
                };
                match previous {
                    Err(code) => code.as_str(),
                    Ok(previous) => outcome(accept_key_set(
                        previous.as_ref(),
                        &pins(&case["pins"]),
                        &new,
                        sig.as_deref(),
                    )),
                }
            }
        };
        let expect = case["expect"].as_str().unwrap();
        match (got == expect, PENDING.contains(&name)) {
            (false, false) => failures.push(format!("{name}: expected {expect}, got {got}")),
            (true, true) => failures.push(format!("{name}: passes; take it off PENDING")),
            _ => {}
        }
        count += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(count >= 20, "only {count} key set vectors");
}

const SET: &str = r#"{"$type":"org.legiblerecords.keys","version":1,"publisher":"acme.example","updated_at":"2026-11-24T00:00:00Z","keys":[
  {"id":"2025-06","alg":"ed25519","public_key":"Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc","created_at":"2025-06-01T00:00:00Z","revoked_at":"2026-06-01T00:00:00Z"},
  {"id":"2026-11","alg":"ed25519","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","created_at":"2026-11-24T00:00:00Z"},
  {"id":"2030-01","alg":"ed448","public_key":"short","created_at":"2026-11-24T00:00:00Z"}]}"#;

fn pin(id: &str, key: &str) -> Pin {
    Pin {
        publisher: "acme.example".to_owned(),
        id: id.to_owned(),
        public_key: from_b64url(key).unwrap().try_into().unwrap(),
    }
}

#[test]
fn revoked_in_key_set_overrides_pin() {
    let mut trust = Trust::default();
    trust.pins.push(pin(
        "2025-06",
        "Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc",
    ));
    assert!(matches!(
        trust.lookup("acme.example", "2025-06"),
        Lookup::Found(_, KeyState::Active)
    ));
    trust.key_sets.insert(
        "acme.example".to_owned(),
        KeySet::parse(SET.as_bytes()).unwrap(),
    );
    match trust.lookup("acme.example", "2025-06") {
        Lookup::Found(key, state) => {
            assert_eq!(state, KeyState::Revoked);
            assert_eq!(
                b64url(&key.key),
                "Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc"
            );
        }
        Lookup::Unknown => panic!("pinned key is known"),
    }
    // A pin under another id for the same revoked key is revoked too.
    trust
        .pins
        .push(pin("other", "Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc"));
    assert!(matches!(
        trust.lookup("acme.example", "other"),
        Lookup::Found(_, KeyState::Revoked)
    ));
}

#[test]
fn approved_keys_are_trusted_like_pins() {
    let mut trust = Trust::default();
    assert_eq!(trust.lookup("acme.example", "2026-11"), Lookup::Unknown);
    assert!(!trust.pins_publisher("acme.example"));
    trust.approved.push(pin(
        "2026-11",
        "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
    ));
    assert!(matches!(
        trust.lookup("acme.example", "2026-11"),
        Lookup::Found(_, KeyState::Active)
    ));
    assert!(trust.pins_publisher("acme.example"));
    assert!(!trust.pins_publisher("other.example"));
}

#[test]
fn unknown_alg_keys_are_not_trusted() {
    let mut trust = Trust::default();
    trust.key_sets.insert(
        "acme.example".to_owned(),
        KeySet::parse(SET.as_bytes()).unwrap(),
    );
    assert_eq!(trust.lookup("acme.example", "2030-01"), Lookup::Unknown);
    assert!(matches!(
        trust.lookup("acme.example", "2026-11"),
        Lookup::Found(_, KeyState::Active)
    ));
}

#[test]
fn parse_refuses_what_is_not_a_key_set() {
    for bad in [
        "not json",
        "[]",
        r#"{"$type":"org.legiblerecords.keys","version":1,"publisher":"acme.example","keys":[]}"#,
        &SET.replace("2026-11-24T00:00:00Z\",\"keys", "yesterday\",\"keys"),
        &SET.replace("\"2026-11\"", "\"2025-06\""),
    ] {
        assert_eq!(
            KeySet::parse(bad.as_bytes()).unwrap_err(),
            Code::BadKeySet,
            "{bad}"
        );
    }
}
