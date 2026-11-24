//! Encrypted bundles and feeds: age, with the signature and the download
//! checked over the stored ciphertext.
#![cfg(feature = "age")]

use std::collections::BTreeMap;

use age::secrecy::ExposeSecret;
use legible_records::age::{decrypt, encrypt, is_encrypted};
use legible_records::bundle::{pack_with, sha256_hex, Input, Limits, PackOptions};
use legible_records::code::Code;
use legible_records::feed::{
    parse_connection, pull, Connection, Fetched, IndexOutcome, NoKeySource, PullOptions,
    PullReport, Source, StreamOutcome, MAX_INDEX_BYTES,
};
use legible_records::keys::Pin;
use legible_records::sign::{sign, Context, SigningKey};
use serde_json::json;

/// A cap on decrypted size that the tests' small files never reach.
const BIG: u64 = 1 << 20;

/// Test-only seed. Never use it for anything real.
fn key() -> SigningKey {
    SigningKey::from_seed("acme.example", "a", [7; 32]).unwrap()
}

fn pin() -> Pin {
    let public = key().public();
    Pin {
        publisher: public.publisher,
        id: public.id,
        alg: "ed25519".to_owned(),
        public_key: public.key,
    }
}

fn conn() -> Connection {
    let mut conn = parse_connection(
        &serde_json::to_vec(&json!({
            "$type": "org.legiblerecords.feed-connection", "version": 1,
            "feed": "acme.example/track",
            "location": {"kind": "https", "url": "https://feeds.acme.example/track/"},
            "auth": {"method": "none"},
        }))
        .unwrap(),
    )
    .unwrap();
    conn.pins = vec![pin()];
    conn
}

struct Identity {
    secret: String,
    recipient: String,
}

fn new_identity() -> Identity {
    let identity = age::x25519::Identity::generate();
    Identity {
        secret: format!(
            "# invented, for tests\n{}\n",
            identity.to_string().expose_secret()
        ),
        recipient: identity.to_public().to_string(),
    }
}

#[derive(Default)]
struct Mem(BTreeMap<String, Vec<u8>>);

impl Source for Mem {
    fn get(&mut self, path: &str, _etag: Option<&str>) -> Result<Fetched, String> {
        Ok(match self.0.get(path) {
            Some(bytes) => Fetched::Found {
                bytes: bytes.clone(),
                etag: None,
            },
            None => Fetched::NotFound,
        })
    }
}

/// An encrypted feed with one stream, `feed.sig` over the ciphertext.
fn encrypted_feed(recipient: &str, armored_index: bool) -> Mem {
    let mut source = Mem::default();
    let inputs = vec![Input {
        name: "note.json".to_owned(),
        bytes: br#"{"$type":"example.note","version":1,"id":"n1","text":"Invented"}"#.to_vec(),
    }];
    let signer = key();
    let options = PackOptions {
        produced_by: None,
        published_at: Some("2026-11-24T10:00:00Z".to_owned()),
        feed: Some(("acme.example/track".to_owned(), "notes".to_owned())),
        signer: Some(&signer),
        ..PackOptions::default()
    };
    let zip = pack_with(&inputs, &[], &options).unwrap().zip;
    let sealed = encrypt(&zip, std::slice::from_ref(&recipient.to_owned())).unwrap();
    let sha = sha256_hex(&sealed);
    let path = format!("bundles/{sha}.zip.age");
    let index = serde_json::to_vec(&json!({
        "$type": "org.legiblerecords.feed", "version": 1, "id": "acme.example/track",
        "publisher": "acme.example", "audience": "Invented", "updated_at": "2026-11-24T10:00:00Z",
        "streams": [{"id": "notes", "title": "Invented", "record_types": ["example.note"],
            "bundle": path, "sha256": sha, "published_at": "2026-11-24T10:00:00Z"}],
    }))
    .unwrap();
    let mut sealed_index = encrypt(&index, std::slice::from_ref(&recipient.to_owned())).unwrap();
    if armored_index {
        sealed_index = armored_for(&index, recipient);
    }
    source.0.insert(path, sealed);
    source.0.insert(
        "feed.sig".to_owned(),
        sign(&signer, Context::Feed, &sealed_index).to_bytes(),
    );
    source.0.insert("feed.json.age".to_owned(), sealed_index);
    source
}

/// An armored age file holding `index` for `recipient`.
fn armored_for(index: &[u8], recipient: &str) -> Vec<u8> {
    use std::io::Write;
    let recipient: age::x25519::Recipient = recipient.parse().unwrap();
    let mut out = Vec::new();
    let armored =
        age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor).unwrap();
    let mut writer = age::Encryptor::with_recipients(std::iter::once(&recipient as _))
        .unwrap()
        .wrap_output(armored)
        .unwrap();
    writer.write_all(index).unwrap();
    writer.finish().unwrap().finish().unwrap();
    out
}

fn read(source: &mut Mem, identity: Option<&str>) -> PullReport {
    pull(
        source,
        &mut NoKeySource,
        &conn(),
        None,
        &mut |_| Ok(()),
        &PullOptions {
            identity,
            ..PullOptions::default()
        },
    )
}

#[test]
fn round_trip_binary_and_armored() {
    let id = new_identity();
    let sealed = encrypt(b"invented", std::slice::from_ref(&id.recipient)).unwrap();
    assert!(is_encrypted(&sealed));
    assert_eq!(decrypt(&sealed, &id.secret, BIG).unwrap(), b"invented");
    let armored = armored_for(b"invented", &id.recipient);
    assert!(is_encrypted(&armored));
    assert_eq!(decrypt(&armored, &id.secret, BIG).unwrap(), b"invented");
    assert!(!is_encrypted(b"PK\x03\x04"));
    assert!(!is_encrypted(b""));
}

#[test]
fn encrypted_feed_reads() {
    let id = new_identity();
    for armored in [false, true] {
        let mut source = encrypted_feed(&id.recipient, armored);
        let report = read(&mut source, Some(&id.secret));
        assert_eq!(report.index, IndexOutcome::Accepted, "armored {armored}");
        assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
    }
}

#[test]
fn feed_sig_over_plaintext_is_refused() {
    let id = new_identity();
    let mut source = encrypted_feed(&id.recipient, false);
    // A signature over what the index says once decrypted isn't one over the
    // stored bytes.
    let sealed = source.0["feed.json.age"].clone();
    let plain = decrypt(&sealed, &id.secret, BIG).unwrap();
    source.0.insert(
        "feed.sig".to_owned(),
        sign(&key(), Context::Feed, &plain).to_bytes(),
    );
    let report = read(&mut source, Some(&id.secret));
    assert_eq!(report.index, IndexOutcome::Refused(Code::BadSignature));
}

#[test]
fn plain_and_encrypted_refused() {
    let id = new_identity();
    let mut source = encrypted_feed(&id.recipient, false);
    source.0.insert("feed.json".to_owned(), b"{}".to_vec());
    let report = read(&mut source, Some(&id.secret));
    assert_eq!(report.index, IndexOutcome::Refused(Code::PlainAndEncrypted));
}

#[test]
fn bundle_download_is_checked_over_the_ciphertext() {
    let id = new_identity();
    let mut source = encrypted_feed(&id.recipient, false);
    let path = source
        .0
        .keys()
        .find(|k| k.ends_with(".zip.age"))
        .unwrap()
        .clone();
    // The same bundle sealed again has other bytes, so another hash.
    let plain = decrypt(&source.0[&path], &id.secret, BIG).unwrap();
    source.0.insert(
        path,
        encrypt(&plain, std::slice::from_ref(&id.recipient)).unwrap(),
    );
    let report = read(&mut source, Some(&id.secret));
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(
        report.streams["notes"],
        StreamOutcome::Refused(Code::DownloadMismatch)
    );
}

#[test]
fn wrong_identity_fails_the_index_not_panics() {
    let id = new_identity();
    let other = new_identity();
    let mut source = encrypted_feed(&id.recipient, false);
    match read(&mut source, Some(&other.secret)).index {
        IndexOutcome::Failed(message) => {
            assert!(message.contains("feed.json.age"), "{message}");
            assert!(!message.contains(other.secret.trim()), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn wrong_identity_fails_stream_not_panics() {
    let id = new_identity();
    let other = new_identity();
    // An index sealed to both, bundles sealed to the first only.
    let mut source = encrypted_feed(&id.recipient, false);
    let index = decrypt(&source.0["feed.json.age"], &id.secret, BIG).unwrap();
    let sealed = encrypt(&index, std::slice::from_ref(&other.recipient)).unwrap();
    source.0.insert(
        "feed.sig".to_owned(),
        sign(&key(), Context::Feed, &sealed).to_bytes(),
    );
    source.0.insert("feed.json.age".to_owned(), sealed);
    let report = read(&mut source, Some(&other.secret));
    assert_eq!(report.index, IndexOutcome::Accepted);
    match &report.streams["notes"] {
        StreamOutcome::Failed(message) => {
            assert!(message.contains(".zip.age"), "{message}");
            assert!(!message.contains(other.secret.trim()), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn corrupt_ciphertext_fails_not_panics() {
    let id = new_identity();
    let mut sealed = encrypt(b"invented", std::slice::from_ref(&id.recipient)).unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 1;
    assert!(decrypt(&sealed, &id.secret, BIG).is_err());
    assert!(decrypt(b"age-encryption.org/v1\n", &id.secret, BIG).is_err());
    assert!(decrypt(&sealed, "not an identity", BIG).is_err());
}

#[test]
fn encrypted_feed_without_identity_fails_clearly() {
    let id = new_identity();
    let mut source = encrypted_feed(&id.recipient, false);
    match read(&mut source, None).index {
        IndexOutcome::Failed(message) => assert!(message.contains("identity"), "{message}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn decrypt_stops_at_max_bytes() {
    let id = new_identity();
    let sealed = encrypt(b"invented", std::slice::from_ref(&id.recipient)).unwrap();
    assert_eq!(decrypt(&sealed, &id.secret, 8).unwrap(), b"invented");
    let e = decrypt(&sealed, &id.secret, 7).unwrap_err();
    assert!(e.contains("larger than 7 bytes"), "{e}");
}

/// Text that deflate can't shrink much: a long JSON string of hex digits
/// from a fixed generator.
fn noise(len: usize) -> String {
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            char::from_digit((x % 16) as u32, 16).unwrap()
        })
        .collect()
}

#[test]
fn encrypted_bundle_past_limits_fails_before_opening() {
    // The bundle's zip is larger than the limits' stored size, so it isn't
    // decrypted in full: the stream fails rather than being opened.
    let id = new_identity();
    let signer = key();
    let inputs = vec![Input {
        name: "note.json".to_owned(),
        bytes: format!(
            r#"{{"$type":"example.note","version":1,"id":"n1","text":"{}"}}"#,
            noise(400_000)
        )
        .into_bytes(),
    }];
    let options = PackOptions {
        produced_by: None,
        published_at: Some("2026-11-24T10:00:00Z".to_owned()),
        feed: Some(("acme.example/track".to_owned(), "notes".to_owned())),
        signer: Some(&signer),
        ..PackOptions::default()
    };
    let zip = pack_with(&inputs, &[], &options).unwrap().zip;
    let limits = Limits {
        max_files: 10,
        max_total_bytes: 1000,
    };
    assert!(zip.len() as u64 > limits.max_stored_bytes());
    let sealed = encrypt(&zip, std::slice::from_ref(&id.recipient)).unwrap();
    let sha = sha256_hex(&sealed);
    let path = format!("bundles/{sha}.zip.age");
    let index = serde_json::to_vec(&json!({
        "$type": "org.legiblerecords.feed", "version": 1, "id": "acme.example/track",
        "publisher": "acme.example", "audience": "Invented", "updated_at": "2026-11-24T10:00:00Z",
        "streams": [{"id": "notes", "title": "Invented", "record_types": ["example.note"],
            "bundle": path, "sha256": sha, "published_at": "2026-11-24T10:00:00Z"}],
    }))
    .unwrap();
    let sealed_index = encrypt(&index, std::slice::from_ref(&id.recipient)).unwrap();
    let mut source = Mem::default();
    source.0.insert(path, sealed);
    source.0.insert(
        "feed.sig".to_owned(),
        sign(&signer, Context::Feed, &sealed_index).to_bytes(),
    );
    source.0.insert("feed.json.age".to_owned(), sealed_index);
    let report = pull(
        &mut source,
        &mut NoKeySource,
        &conn(),
        None,
        &mut |_| Ok(()),
        &PullOptions {
            identity: Some(&id.secret),
            limits,
            ..PullOptions::default()
        },
    );
    assert_eq!(report.index, IndexOutcome::Accepted);
    match &report.streams["notes"] {
        StreamOutcome::Failed(message) => assert!(message.contains("larger than"), "{message}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn encrypted_index_past_max_index_bytes_fails() {
    let id = new_identity();
    let mut index = vec![b' '; MAX_INDEX_BYTES as usize + 1];
    index[0] = b'{';
    let last = index.len() - 1;
    index[last] = b'}';
    let sealed_index = encrypt(&index, std::slice::from_ref(&id.recipient)).unwrap();
    let mut source = Mem::default();
    source.0.insert(
        "feed.sig".to_owned(),
        sign(&key(), Context::Feed, &sealed_index).to_bytes(),
    );
    source.0.insert("feed.json.age".to_owned(), sealed_index);
    match read(&mut source, Some(&id.secret)).index {
        IndexOutcome::Failed(message) => assert!(message.contains("larger than"), "{message}"),
        other => panic!("{other:?}"),
    }
}
