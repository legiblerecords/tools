//! Signature vectors and unit tests for contexts, keys, time and publishers.

use legible_records::code::Code;
use legible_records::sign::{
    b64url, from_b64url, is_publisher, sign, verify, Context, PublicKey, SignatureFile, SigningKey,
};
use legible_records::time;
use serde_json::Value;

/// A test-only seed. Never use it for anything real.
const TEST_SEED: [u8; 32] = [7; 32];

fn context(name: &str) -> Context {
    match name {
        "manifest" => Context::Manifest,
        "feed" => Context::Feed,
        "keys" => Context::Keys,
        other => panic!("unknown context {other}"),
    }
}

#[test]
fn signature_vectors() {
    let path = format!(
        "{}/tests/vectors/signatures.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let file: Value = serde_json::from_str(&text).expect("vectors are JSON");
    let cases = file["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let key_bytes = from_b64url(case["public_key"].as_str().unwrap()).unwrap();
        let signature_file = &case["signature_file"];
        let key = PublicKey {
            publisher: signature_file["publisher"].as_str().unwrap().to_owned(),
            id: signature_file["key"].as_str().unwrap().to_owned(),
            key: key_bytes.try_into().expect("32 bytes"),
        };
        let message = from_b64url(case["message_b64"].as_str().unwrap()).unwrap();
        let ctx = context(case["context"].as_str().unwrap());
        let bytes = serde_json::to_vec(signature_file).unwrap();
        let result = SignatureFile::parse(&bytes).and_then(|sig| verify(&key, ctx, &message, &sig));
        match case["expect"].as_str().unwrap() {
            "valid" => assert_eq!(result, Ok(()), "{name}"),
            code => assert_eq!(result, Err(Code::parse(code).expect(code)), "{name}"),
        }
    }
}

#[test]
fn prefixes_are_exact() {
    assert_eq!(Context::Manifest.prefix(), b"legible-records/v1 manifest\n");
    assert_eq!(Context::Feed.prefix(), b"legible-records/v1 feed\n");
    assert_eq!(Context::Keys.prefix(), b"legible-records/v1 keys\n");
}

#[test]
fn round_trips_secret_key_json() {
    let key = SigningKey::from_seed("acme.example", "2026-11", TEST_SEED).unwrap();
    let again = SigningKey::from_json(&key.to_json()).unwrap();
    assert_eq!(again.publisher, "acme.example");
    assert_eq!(again.id, "2026-11");
    assert_eq!(again.public().key, key.public().key);
    let json: Value = serde_json::from_slice(&key.to_json()).unwrap();
    assert_eq!(json["$type"], "legible-secret-key");
    assert_eq!(json["alg"], "ed25519");
    assert!(SigningKey::from_json(b"{}").is_err());
    assert!(SigningKey::from_seed("Acme", "x", TEST_SEED).is_err());
}

#[test]
fn signs_and_verifies() {
    let key = SigningKey::generate("acme.example", "k1").unwrap();
    let sig = sign(&key, Context::Feed, b"hello");
    assert_eq!(verify(&key.public(), Context::Feed, b"hello", &sig), Ok(()));
    assert_eq!(
        verify(&key.public(), Context::Manifest, b"hello", &sig),
        Err(Code::BadSignature)
    );
    let reparsed = SignatureFile::parse(&sig.to_bytes()).unwrap();
    assert_eq!(
        verify(&key.public(), Context::Feed, b"hello", &reparsed),
        Ok(())
    );
    let mut other = key.public();
    other.publisher = "other.example".into();
    assert_eq!(
        verify(&other, Context::Feed, b"hello", &sig),
        Err(Code::PublisherMismatch)
    );
    let mut other = key.public();
    other.id = "k2".into();
    assert_eq!(
        verify(&other, Context::Feed, b"hello", &sig),
        Err(Code::UnknownKey)
    );
}

#[test]
fn signature_file_shape() {
    let bad = |s: &str| SignatureFile::parse(s.as_bytes()).unwrap_err();
    assert_eq!(bad("not json"), Code::BadSignatureFile);
    assert_eq!(bad("[]"), Code::BadSignatureFile);
    assert_eq!(
        bad(r#"{"alg":"ed25519","publisher":"a.example","key":"k"}"#),
        Code::BadSignatureFile
    );
    let sig = b64url(&[0u8; 64]);
    assert_eq!(
        bad(&format!(
            r#"{{"alg":"ed25519","publisher":"a.example","key":"k","signature":"{sig}","extra":1}}"#
        )),
        Code::BadSignatureFile
    );
    assert_eq!(
        bad(&format!(
            r#"{{"alg":"ed25519","publisher":"a.example","key":"k","signature":"{}"}}"#,
            b64url(&[0u8; 63])
        )),
        Code::BadSignatureFile
    );
}

#[test]
fn rejects_non_domain_publishers() {
    for bad in [
        "Acme.example",
        "acme",
        "https://acme.example",
        "acme.example:443",
        "acme.example/x",
        "-a.example",
        "a-.example",
        "a..example",
        ".a.example",
        "a.example.",
        "",
        "a.example\n",
    ] {
        assert!(!is_publisher(bad), "{bad:?}");
    }
    assert!(is_publisher("acme.example"));
    assert!(is_publisher("a-b.co.uk"));
    let long = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(long.len(), 253);
    assert!(is_publisher(&long));
    assert!(!is_publisher(&format!("{long}x")));
}

#[test]
fn base64url_has_no_padding() {
    assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
    assert_eq!(from_b64url("-_8").unwrap(), vec![0xfb, 0xff]);
    assert!(from_b64url("-_8=").is_err());
    assert!(from_b64url("not base64!").is_err());
}

#[test]
fn time_orders_across_offsets() {
    assert_eq!(
        time::parse("2026-11-24T11:00:00+01:00").unwrap(),
        time::parse("2026-11-24T10:00:00Z").unwrap()
    );
    assert!(
        time::parse("2026-11-24T10:00:01Z").unwrap() > time::parse("2026-11-24T10:00:00Z").unwrap()
    );
    assert!(time::parse("yesterday").is_err());
    assert!(time::parse("2026-11-24").is_err());
}

#[test]
fn time_formats_utc_milliseconds() {
    let t = time::parse("2026-11-24T11:00:00+01:00").unwrap();
    assert_eq!(time::format(t), "2026-11-24T10:00:00.000Z");
    let t = time::parse("2026-11-24T10:00:00.1234Z").unwrap();
    assert_eq!(time::format(t), "2026-11-24T10:00:00.123Z");
}

#[test]
fn codes_round_trip() {
    for code in Code::ALL {
        assert_eq!(Code::parse(code.as_str()), Some(*code));
    }
    assert_eq!(Code::ALL.len(), 20);
    assert_eq!(
        Code::UnsignedFromPinnedPublisher.as_str(),
        "unsigned_from_pinned_publisher"
    );
    assert_eq!(Code::KeySetRollback.as_str(), "key_set_rollback");
    assert_eq!(Code::parse("nope"), None);
}
