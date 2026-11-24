//! Key set vectors and trust.

use legible_records::code::Code;
use legible_records::keys::{
    decide_key_set, parse_pin, KeySet, KeySetDecision, KeyState, Lookup, Pin, Trust,
};
use legible_records::sign::{b64url, from_b64url};
use legible_records::time;

use serde_json::Value;

fn pins(value: &Value) -> Vec<Pin> {
    value
        .as_array()
        .expect("pins")
        .iter()
        .map(|p| {
            let field = |name: &str| p[name].as_str().unwrap();
            parse_pin(
                field("publisher"),
                field("id"),
                field("alg"),
                field("public_key"),
            )
            .unwrap()
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

/// The reader's clock when a vector gives no `now`.
const DEFAULT_NOW: &str = "2026-12-01T00:00:00Z";

/// Vectors this reader doesn't pass yet; each must still fail, so the list
/// only shrinks.
const PENDING: &[&str] = &[];

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
        let now = time::parse(case["now"].as_str().unwrap_or(DEFAULT_NOW)).unwrap();
        let previous = (!case["previous"].is_null()).then(|| {
            KeySet::parse(&serde_json::to_vec(&case["previous"]).unwrap()).expect("previous")
        });
        // The key set is taken to be fetched from the domain it names.
        let verdict = decide_key_set(
            previous.as_ref(),
            &pins(&case["pins"]),
            &keys_bytes,
            sig.as_deref(),
            now,
            None,
        );
        let got = outcome(verdict.outcome);
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
  {"id":"2030-01","alg":"ed448","public_key":"zRSzf5VulTGU_3-3Oz2B3MVh1hp1OAlLfD4aZD7l86o","created_at":"2026-11-24T00:00:00Z"}]}"#;

fn pin(id: &str, key: &str) -> Pin {
    Pin {
        publisher: "acme.example".to_owned(),
        id: id.to_owned(),
        alg: "ed25519".to_owned(),
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
        other => panic!("pinned key is known: {other:?}"),
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
    assert_eq!(trust.lookup("acme.example", "2030-01"), Lookup::UnknownAlg);
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

#[test]
fn endorsement_in_another_context_is_bad() {
    use legible_records::sign::{sign, Context, SigningKey};
    // Test-only seed.
    let key = SigningKey::from_seed("acme.example", "2026-11", [7; 32]).unwrap();
    let public = b64url(&key.public().key);
    let set = format!(
        r#"{{"$type":"org.legiblerecords.keys","version":1,"publisher":"acme.example","updated_at":"2026-11-24T00:00:00Z","keys":[{{"id":"2026-11","alg":"ed25519","public_key":"{public}","created_at":"2026-11-24T00:00:00Z"}},{{"id":"next","alg":"ed25519","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","created_at":"2026-11-24T00:00:00Z"}}]}}"#
    );
    let anchors = [pin("2026-11", &public)];
    let now = time::parse("2026-12-01T00:00:00Z").unwrap();
    for (context, expect) in [
        (Context::Manifest, Err(Code::BadEndorsement)),
        (Context::Feed, Err(Code::BadEndorsement)),
        (Context::Keys, Ok(KeySetDecision::Accepted)),
    ] {
        let sig = sign(&key, context, set.as_bytes()).to_bytes();
        let verdict = decide_key_set(None, &anchors, set.as_bytes(), Some(&sig), now, None);
        assert_eq!(verdict.outcome, expect, "{context:?}");
    }
}

#[test]
fn served_set_must_name_its_domain_and_not_run_ahead() {
    let now = time::parse("2026-11-24T00:00:00Z").unwrap();
    let verdict = decide_key_set(None, &[], SET.as_bytes(), None, now, Some("other.example"));
    assert_eq!(verdict.outcome, Err(Code::BadKeySet));
    assert!(verdict.set.is_none());
    let early = time::parse("2026-11-22T23:59:59Z").unwrap();
    let verdict = decide_key_set(None, &[], SET.as_bytes(), None, early, Some("acme.example"));
    assert_eq!(verdict.outcome, Err(Code::BadKeySet));
}

#[test]
fn pins_parse_in_one_place() {
    use legible_records::keys::parse_pin_text;
    let good = "acme.example/2026-11=A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
    let pin = parse_pin_text(good).unwrap();
    assert_eq!(
        (pin.publisher.as_str(), pin.id.as_str(), pin.alg.as_str()),
        ("acme.example", "2026-11", "ed25519")
    );
    for bad in [
        "acme.example/2026-11",
        "acme.example=A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
        "10.0.0.1/k=A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
        // Not canonical: the last character's unused bits aren't zero.
        "acme.example/k=A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbh",
    ] {
        assert!(parse_pin_text(bad).is_err(), "{bad}");
    }
    assert!(parse_pin(
        "acme.example",
        "k",
        "ml-dsa-44",
        "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
    )
    .is_err());
}
