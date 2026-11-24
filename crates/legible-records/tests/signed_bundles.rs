//! Signed bundles: the spec's bundle vectors, and packing with a signer.

use std::io::{Cursor, Read};

use legible_records::bundle::{
    add_signature, check_signature, open, pack, pack_with, verify, verify_at, Input, Limits,
    PackOptions, SignatureStatus, SIGNATURE,
};
use legible_records::code::Code;
use legible_records::keys::{parse_pin, KeySet, Pin, Trust};
use legible_records::sign::SigningKey;
use legible_records::time;
use serde_json::{json, Value};

/// A test-only seed. Never use it for anything real.
const TEST_SEED: [u8; 32] = [7; 32];

fn trust_from(value: &Value) -> Trust {
    let mut trust = Trust::default();
    for p in value["pins"].as_array().expect("pins") {
        let field = |name: &str| p[name].as_str().unwrap();
        trust.pins.push(
            parse_pin(
                field("publisher"),
                field("id"),
                field("alg"),
                field("public_key"),
            )
            .unwrap(),
        );
    }
    for set in value["key_sets"].as_array().expect("key_sets") {
        let parsed = KeySet::parse(&serde_json::to_vec(set).unwrap()).expect("key set parses");
        trust.key_sets.insert(parsed.publisher.clone(), parsed);
    }
    trust
}

/// Vectors this reader doesn't pass yet; each must still fail, so the list
/// only shrinks.
const PENDING: &[&str] = &[];

#[test]
fn signed_bundle_vectors() {
    let dir = format!("{}/tests/vectors/bundles", env!("CARGO_MANIFEST_DIR"));
    let (mut count, mut failures) = (0, Vec::new());
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let case: Value =
            serde_json::from_slice(&std::fs::read(path.join("case.json")).unwrap()).unwrap();
        let name = case["name"].as_str().unwrap();
        let zip = std::fs::read(path.join("bundle.zip")).unwrap();
        let trust = trust_from(&case["trust"]);
        let expected = case["expected_publisher"].as_str();
        let now = time::parse(case["now"].as_str().unwrap_or("2026-12-01T00:00:00Z")).unwrap();
        // The zip's entry names are read first; the signature is checked
        // before the bundle's own checks.
        let got = match open(&zip, Limits::default()) {
            Err(_) => json!({"error": Code::BadBundle.as_str()}),
            Ok(opened) => match check_signature(&opened, &trust, expected) {
                Err(code) => json!({"error": code.as_str()}),
                Ok(_) if !verify_at(&opened, &[], now).problems.is_empty() => {
                    json!({"error": Code::BadBundle.as_str()})
                }
                Ok(SignatureStatus::Verified { publisher, key, .. }) => {
                    json!({"status": "verified", "publisher": publisher, "key": key})
                }
                Ok(SignatureStatus::Unverified) => json!({"status": "unverified"}),
            },
        };
        let expect = &case["expect"];
        match (&got == expect, PENDING.contains(&name)) {
            (false, false) => failures.push(format!("{name}: expected {expect}, got {got}")),
            (true, true) => failures.push(format!("{name}: passes; take it off PENDING")),
            _ => {}
        }
        count += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(count >= 10, "only {count} bundle vectors");
}

fn key() -> SigningKey {
    SigningKey::from_seed("acme.example", "2026-11", TEST_SEED).unwrap()
}

fn trusting(key: &SigningKey) -> Trust {
    let public = key.public();
    Trust {
        pins: vec![Pin {
            publisher: public.publisher,
            id: public.id,
            alg: "ed25519".to_owned(),
            public_key: public.key,
        }],
        ..Trust::default()
    }
}

fn inputs() -> Vec<Input> {
    vec![
        Input {
            name: "mfa.json".to_owned(),
            bytes: br#"{"$type":"tech.monorail.controls.control","version":1,"id":"mfa","title":"MFA"}"#.to_vec(),
        },
        Input {
            name: "review.pdf".to_owned(),
            bytes: b"%PDF-1.4 invented".to_vec(),
        },
    ]
}

fn options(signer: Option<&SigningKey>) -> PackOptions<'_> {
    PackOptions {
        produced_by: Some(json!({"app": "test"})),
        published_at: Some("2026-11-24T10:00:00Z".to_owned()),
        feed: Some(("acme.example/controls".to_owned(), "main".to_owned())),
        signer,
        ..PackOptions::default()
    }
}

#[test]
fn pack_with_signer_verifies() {
    let key = key();
    let packed = pack_with(&inputs(), &[], &options(Some(&key))).unwrap();
    assert_eq!(packed.manifest["published_at"], "2026-11-24T10:00:00Z");
    assert_eq!(
        packed.manifest["feed"],
        json!({"id": "acme.example/controls", "stream": "main"})
    );
    let opened = open(&packed.zip, Limits::default()).unwrap();
    assert!(opened.signature.is_some());
    assert!(!opened.files.contains_key(SIGNATURE));
    assert_eq!(
        check_signature(&opened, &trusting(&key), Some("acme.example")),
        Ok(SignatureStatus::Verified {
            publisher: "acme.example".to_owned(),
            key: "2026-11".to_owned(),
            public_key: key.public().key,
        })
    );
    // Another key under the same id doesn't verify.
    let other = SigningKey::from_seed("acme.example", "2026-11", [8; 32]).unwrap();
    assert_eq!(
        check_signature(&opened, &trusting(&other), Some("acme.example")),
        Err(Code::BadSignature)
    );
}

#[test]
fn add_signature_matches_pack_with_signer() {
    let key = key();
    let plain = pack_with(&inputs(), &[], &options(None)).unwrap();
    let signed = add_signature(&plain.zip, &key, Limits::default()).unwrap();
    let direct = pack_with(&inputs(), &[], &options(Some(&key))).unwrap();
    assert_eq!(signed, direct.zip);
}

#[test]
fn add_signature_twice_is_refused() {
    let key = key();
    let packed = pack_with(&inputs(), &[], &options(Some(&key))).unwrap();
    let problems = add_signature(&packed.zip, &key, Limits::default()).unwrap_err();
    assert!(
        problems.iter().any(|p| p.contains("already signed")),
        "{problems:?}"
    );
}

#[test]
fn manifest_sig_is_not_an_unlisted_file() {
    let key = key();
    let packed = pack_with(&inputs(), &[], &options(Some(&key))).unwrap();
    let opened = open(&packed.zip, Limits::default()).unwrap();
    assert_eq!(verify(&opened, &[]).problems, Vec::<String>::new());
    let mut zip = zip::ZipArchive::new(Cursor::new(&packed.zip)).unwrap();
    let mut sig = Vec::new();
    zip.by_name(SIGNATURE)
        .unwrap()
        .read_to_end(&mut sig)
        .unwrap();
    assert_eq!(opened.signature, Some(sig));
}

#[test]
fn pack_is_unsigned_and_unverified() {
    let packed = pack(&inputs(), &[], None).unwrap();
    let opened = open(&packed.zip, Limits::default()).unwrap();
    assert_eq!(opened.signature, None);
    assert_eq!(
        check_signature(&opened, &Trust::default(), None),
        Ok(SignatureStatus::Unverified)
    );
}

#[test]
fn unsigned_from_a_trusted_publisher_is_refused() {
    let key = key();
    let packed = pack_with(&inputs(), &[], &options(None)).unwrap();
    let opened = open(&packed.zip, Limits::default()).unwrap();
    // Pinned.
    assert_eq!(
        check_signature(&opened, &trusting(&key), Some("acme.example")),
        Err(Code::UnsignedFromPinnedPublisher)
    );
    // Approved.
    let mut approved = trusting(&key);
    approved.approved = std::mem::take(&mut approved.pins);
    assert_eq!(
        check_signature(&opened, &approved, Some("acme.example")),
        Err(Code::UnsignedFromPinnedPublisher)
    );
    // A held key set, with no pin.
    let set = KeySet::parse(
        &serde_json::to_vec(&json!({
            "$type": "org.legiblerecords.keys",
            "version": 1,
            "publisher": "acme.example",
            "updated_at": "2026-11-24T00:00:00Z",
            "keys": [{"id": "2026-11", "alg": "ed25519",
                      "public_key": legible_records::sign::b64url(&key.public().key),
                      "created_at": "2026-11-24T00:00:00Z"}]
        }))
        .unwrap(),
    )
    .unwrap();
    let mut held = Trust::default();
    held.key_sets.insert("acme.example".to_owned(), set);
    assert_eq!(
        check_signature(&opened, &held, Some("acme.example")),
        Err(Code::UnsignedFromPinnedPublisher)
    );
    // Another publisher's trust doesn't matter, nor does having no expectation.
    assert_eq!(
        check_signature(&opened, &held, Some("other.example")),
        Ok(SignatureStatus::Unverified)
    );
    assert_eq!(
        check_signature(&opened, &held, None),
        Ok(SignatureStatus::Unverified)
    );
}

#[test]
fn signature_checks_run_in_order() {
    let key = key();
    let signed = pack_with(&inputs(), &[], &options(Some(&key))).unwrap();
    let mut opened = open(&signed.zip, Limits::default()).unwrap();
    let trust = trusting(&key);
    // Publisher mismatch is found before the key is looked up.
    assert_eq!(
        check_signature(&opened, &Trust::default(), Some("other.example")),
        Err(Code::PublisherMismatch)
    );
    assert_eq!(
        check_signature(&opened, &Trust::default(), Some("acme.example")),
        Err(Code::UnknownKey)
    );
    opened.signature = Some(b"{}".to_vec());
    assert_eq!(
        check_signature(&opened, &trust, Some("other.example")),
        Err(Code::BadSignatureFile)
    );
    opened.signature = Some(
        format!(
            r#"{{"alg":"rsa","publisher":"acme.example","key":"2026-11","signature":"{}"}}"#,
            "A".repeat(86)
        )
        .into_bytes(),
    );
    assert_eq!(
        check_signature(&opened, &trust, Some("other.example")),
        Err(Code::UnknownAlg)
    );
}

/// A zip of exactly these entries, in this order.
fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in entries {
        writer
            .start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

/// The entries of an opened bundle, as a zip would hold them.
fn entries_of(opened: &legible_records::bundle::Opened) -> Vec<(String, Vec<u8>)> {
    std::iter::once(("manifest.json".to_owned(), opened.manifest_bytes.clone()))
        .chain(opened.files.iter().map(|(p, b)| (p.clone(), b.clone())))
        .collect()
}

#[test]
fn nested_manifest_sig_is_an_ordinary_file() {
    let packed = pack_with(&inputs(), &[], &options(None)).unwrap();
    let opened = open(&packed.zip, Limits::default()).unwrap();
    let mut entries = entries_of(&opened);
    entries.push(("x/manifest.sig".to_owned(), b"not a signature".to_vec()));
    let borrowed: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice()))
        .collect();
    let zip = zip_of(&borrowed);
    let nested = open(&zip, Limits::default()).unwrap();
    assert_eq!(nested.signature, None);
    assert_eq!(
        nested.files.get("x/manifest.sig").map(Vec::as_slice),
        Some(&b"not a signature"[..])
    );
    let problems = verify(&nested, &[]).problems;
    assert!(
        problems
            .iter()
            .any(|p| p.contains("x/manifest.sig") && p.contains("not listed")),
        "{problems:?}"
    );
}

#[test]
fn two_top_level_manifest_sigs_fail_to_open() {
    let key = key();
    let signed = pack_with(&inputs(), &[], &options(Some(&key))).unwrap();
    let opened = open(&signed.zip, Limits::default()).unwrap();
    let sig = opened.signature.clone().unwrap();
    let mut entries = entries_of(&opened);
    // A zip writer refuses repeated names, so write one under a name of the
    // same length and rename it in the stored bytes.
    entries.push(("manifest.sig".to_owned(), sig.clone()));
    entries.push(("manifest.sih".to_owned(), sig));
    let borrowed: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice()))
        .collect();
    let mut zip = zip_of(&borrowed);
    let from = b"manifest.sih";
    let mut renamed = 0;
    for i in 0..zip.len() - from.len() {
        if &zip[i..i + from.len()] == from {
            zip[i..i + from.len()].copy_from_slice(b"manifest.sig");
            renamed += 1;
        }
    }
    assert_eq!(renamed, 2, "local header and central directory");
    let problems = open(&zip, Limits::default()).unwrap_err();
    assert!(
        problems.iter().any(|p| p.contains("appears twice")),
        "{problems:?}"
    );
}

#[test]
fn add_signature_signs_non_canonical_stored_manifest() {
    let key = key();
    let packed = pack_with(&inputs(), &[], &options(None)).unwrap();
    let opened = open(&packed.zip, Limits::default()).unwrap();
    // The same manifest, written compactly: valid, but not how a writer writes it.
    let compact = serde_json::to_vec(&opened.manifest).unwrap();
    assert_ne!(compact, opened.manifest_bytes);
    let mut entries = entries_of(&opened);
    entries[0].1 = compact.clone();
    let borrowed: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice()))
        .collect();
    let zip = zip_of(&borrowed);
    let signed = add_signature(&zip, &key, Limits::default()).unwrap();
    let reopened = open(&signed, Limits::default()).unwrap();
    assert_eq!(reopened.manifest_bytes, compact);
    assert_eq!(
        check_signature(&reopened, &trusting(&key), Some("acme.example")),
        Ok(SignatureStatus::Verified {
            publisher: "acme.example".to_owned(),
            key: "2026-11".to_owned(),
            public_key: key.public().key,
        })
    );
}
