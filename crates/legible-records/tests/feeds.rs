//! Feeds: the spec's feed vectors, connection files, reader state and `pull`.

use std::collections::BTreeMap;

use legible_records::bundle::{pack_with, sha256_hex, Input, PackOptions, SignatureStatus};
use legible_records::code::Code;
use legible_records::feed::{
    parse_connection, parse_feed, pull, Auth, Connection, Delivered, DirSource, Fetched,
    IndexOutcome, KeySetFiles, KeySource, Location, NoKeySource, PullOptions, PullReport,
    ReaderState, Source, StreamOutcome, StreamState,
};
use legible_records::keys::{KeySet, Pin};
use legible_records::sign::{b64url, sign, Context, SigningKey};
use serde_json::{json, Value};

fn vectors_dir() -> String {
    format!("{}/tests/vectors/feeds", env!("CARGO_MANIFEST_DIR"))
}

fn stream_str(outcome: &StreamOutcome) -> String {
    match outcome {
        StreamOutcome::Accepted => "accepted".to_owned(),
        StreamOutcome::Unchanged => "unchanged".to_owned(),
        StreamOutcome::Withdrawn => "withdrawn".to_owned(),
        StreamOutcome::Refused(code) => code.as_str().to_owned(),
        StreamOutcome::Failed(message) => format!("failed: {message}"),
    }
}

fn index_str(outcome: &IndexOutcome) -> String {
    match outcome {
        IndexOutcome::Accepted => "ok".to_owned(),
        IndexOutcome::NotModified => "not modified".to_owned(),
        IndexOutcome::Refused(code) => code.as_str().to_owned(),
        IndexOutcome::Failed(message) => format!("failed: {message}"),
    }
}

/// The vector's state in the on-disk form: the same, with `$type` and `version`.
fn state_from(value: &Value) -> Option<ReaderState> {
    if value.is_null() {
        return None;
    }
    let mut value = value.clone();
    value["$type"] = json!("legible-reader-state");
    value["version"] = json!(1);
    Some(ReaderState::parse(&serde_json::to_vec(&value).unwrap()).expect("state parses"))
}

fn load_case(name: &str) -> (Value, Connection, Option<ReaderState>) {
    let dir = format!("{}/{name}", vectors_dir());
    let case: Value =
        serde_json::from_slice(&std::fs::read(format!("{dir}/case.json")).unwrap()).unwrap();
    let conn = parse_connection(&serde_json::to_vec(&case["connection"]).unwrap())
        .unwrap_or_else(|e| panic!("{name}: connection: {e}"));
    let state = state_from(&case["state"]);
    (case, conn, state)
}

#[test]
fn feed_vectors() {
    let mut count = 0;
    for entry in std::fs::read_dir(vectors_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let (case, conn, mut state) = load_case(&name);
        let mut source = DirSource {
            root: path.join("feed"),
        };
        let report = pull(
            &mut source,
            &mut NoKeySource,
            &conn,
            state.as_mut(),
            &mut |_| Ok(()),
            &PullOptions::default(),
        );
        let streams: BTreeMap<String, Value> = report
            .streams
            .iter()
            .map(|(id, o)| (id.clone(), json!(stream_str(o))))
            .collect();
        let got = json!({"index": index_str(&report.index), "streams": streams});
        assert_eq!(got, case["expect"], "{name}");
        count += 1;
    }
    assert!(count >= 18, "only {count} feed vectors");
}

#[test]
fn stateless_replay_is_delivered_with_its_older_published_at() {
    let (_, conn, _) = load_case("stateless-replay");
    let mut source = DirSource {
        root: format!("{}/stateless-replay/feed", vectors_dir()).into(),
    };
    let mut delivered: Vec<Delivered> = Vec::new();
    let report = pull(
        &mut source,
        &mut NoKeySource,
        &conn,
        None,
        &mut |d| {
            delivered.push(d);
            Ok(())
        },
        &PullOptions::default(),
    );
    assert_eq!(report.index, IndexOutcome::Accepted);
    let replayed = delivered
        .iter()
        .find(|d| d.stream.id == "policy-acknowledgments")
        .expect("delivered");
    assert_eq!(replayed.published_at, "2026-11-24T09:00:00Z");
    assert_eq!(replayed.feed_updated_at, "2026-11-24T11:00:00Z");
    let mut ids = replayed.stream_ids.clone();
    ids.sort();
    assert_eq!(
        ids,
        ["access-reviews", "incidents", "policy-acknowledgments"]
    );
    assert!(matches!(
        replayed.signature,
        SignatureStatus::Verified { .. }
    ));
}

#[test]
fn state_round_trips() {
    for name in ["unsigned-index-key-set", "withdrawn", "replay"] {
        let (_, _, state) = load_case(name);
        let state = state.unwrap();
        let bytes = state.to_bytes();
        let again = ReaderState::parse(&bytes).expect("parses");
        assert_eq!(again, state, "{name}");
        assert_eq!(again.to_bytes(), bytes, "{name}");
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["$type"], "legible-reader-state");
        assert_eq!(value["version"], 1);
    }
    assert_eq!(
        ReaderState::parse(&ReaderState::default().to_bytes()).unwrap(),
        ReaderState::default()
    );
}

#[test]
fn state_refuses_a_key_set_under_another_publisher() {
    let (case, _, _) = load_case("unsigned-index-key-set");
    let mut value = case["state"].clone();
    value["$type"] = json!("legible-reader-state");
    value["version"] = json!(1);
    let set = value["key_sets"]["acme.example"].clone();
    value["key_sets"] = json!({ "other.example": set });
    assert!(ReaderState::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn state_refuses_another_type() {
    assert!(ReaderState::parse(
        br#"{"feed_updated_at":null,"streams":{},"key_sets":{},"approved":[]}"#
    )
    .is_err());
}

#[test]
fn failed_delivery_leaves_state() {
    let (_, conn, state) = load_case("one-changed");
    let mut state = state.unwrap();
    let before = state.clone();
    let mut source = DirSource {
        root: format!("{}/one-changed/feed", vectors_dir()).into(),
    };
    let report = pull(
        &mut source,
        &mut NoKeySource,
        &conn,
        Some(&mut state),
        &mut |_| Err("the destination is down".to_owned()),
        &PullOptions::default(),
    );
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(
        report.streams["policy-acknowledgments"],
        StreamOutcome::Failed("the destination is down".to_owned())
    );
    assert_eq!(
        state.streams["policy-acknowledgments"],
        before.streams["policy-acknowledgments"]
    );
    // A failed stream must be retried, so the report gives no ETag to keep.
    assert_eq!(report.etag, None);
}

#[test]
fn accepted_delivery_updates_state() {
    let (_, conn, state) = load_case("one-changed");
    let mut state = state.unwrap();
    let mut source = DirSource {
        root: format!("{}/one-changed/feed", vectors_dir()).into(),
    };
    let report = pull(
        &mut source,
        &mut NoKeySource,
        &conn,
        Some(&mut state),
        &mut |_| Ok(()),
        &PullOptions::default(),
    );
    assert_eq!(
        report.streams["policy-acknowledgments"],
        StreamOutcome::Accepted
    );
    let index = parse_feed(
        &std::fs::read(format!("{}/one-changed/feed/feed.json", vectors_dir())).unwrap(),
    )
    .unwrap();
    let entry = index
        .streams
        .iter()
        .find(|s| s.id == "policy-acknowledgments")
        .unwrap();
    assert_eq!(
        state.streams["policy-acknowledgments"],
        StreamState {
            sha256: entry.sha256.clone(),
            published_at: entry.published_at.clone(),
        }
    );
    assert_eq!(
        state.feed_updated_at.as_deref(),
        Some(index.updated_at.as_str())
    );
}

#[test]
fn withdrawn_stream_leaves_state() {
    let (_, conn, state) = load_case("withdrawn");
    let mut state = state.unwrap();
    let mut source = DirSource {
        root: format!("{}/withdrawn/feed", vectors_dir()).into(),
    };
    let report = pull(
        &mut source,
        &mut NoKeySource,
        &conn,
        Some(&mut state),
        &mut |_| Ok(()),
        &PullOptions::default(),
    );
    assert_eq!(report.streams["incidents"], StreamOutcome::Withdrawn);
    assert!(!state.streams.contains_key("incidents"));
}

#[test]
fn refused_index_leaves_state() {
    for name in ["stale-index", "unsigned-index-key-set"] {
        let (_, conn, state) = load_case(name);
        let mut state = state.unwrap();
        let before = state.clone();
        let mut source = DirSource {
            root: format!("{}/{name}/feed", vectors_dir()).into(),
        };
        let report = pull(
            &mut source,
            &mut NoKeySource,
            &conn,
            Some(&mut state),
            &mut |_| panic!("nothing is delivered from a refused index"),
            &PullOptions::default(),
        );
        assert!(matches!(report.index, IndexOutcome::Refused(_)), "{name}");
        assert!(report.streams.is_empty(), "{name}");
        assert_eq!(state, before, "{name}");
    }
}

fn connection_json(location: Value, auth: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "$type": "org.legiblerecords.feed-connection",
        "version": 1,
        "feed": "acme.example/track",
        "location": location,
        "auth": auth,
    }))
    .unwrap()
}

#[test]
fn connection_requires_bucket_for_s3() {
    let auth = json!({"method": "s3", "access_key_id_env": "K", "secret_access_key_env": "S"});
    let without = connection_json(
        json!({"kind": "s3", "endpoint": "https://storage.acme.example", "region": "auto", "prefix": "feeds/"}),
        auth.clone(),
    );
    let err = parse_connection(&without).unwrap_err();
    assert!(err.contains("bucket"), "{err}");
    let with = connection_json(
        json!({"kind": "s3", "endpoint": "https://storage.acme.example", "region": "auto",
               "bucket": "acme-legible", "prefix": "feeds/"}),
        auth,
    );
    let conn = parse_connection(&with).unwrap();
    assert_eq!(
        conn.location,
        Location::S3 {
            endpoint: "https://storage.acme.example".to_owned(),
            region: "auto".to_owned(),
            bucket: "acme-legible".to_owned(),
            prefix: "feeds/".to_owned(),
            path_style: false,
        }
    );
    assert_eq!(
        conn.auth,
        Auth::S3 {
            access_key_id_env: "K".to_owned(),
            secret_access_key_env: "S".to_owned(),
        }
    );
}

#[test]
fn connection_refusals() {
    let https = json!({"kind": "https", "url": "https://feeds.acme.example/track/"});
    let none = json!({"method": "none"});
    let cases = [
        (
            json!({"kind": "ftp", "url": "ftp://x.example/"}),
            none.clone(),
            "kind",
        ),
        (https.clone(), json!({"method": "magic"}), "method"),
        (https.clone(), json!({"method": "bearer"}), "token_env"),
        (
            https.clone(),
            json!({"method": "bearer", "token_env": "T", "token": "s3cret"}),
            "token",
        ),
        (
            json!({"kind": "https", "url": "https://user:pw@feeds.acme.example/"}),
            none.clone(),
            "userinfo",
        ),
        (
            https.clone(),
            json!({"method": "oauth-client-credentials", "token_url": "https://a:b@auth.acme.example/token",
                   "client_id": "c", "client_secret_env": "S"}),
            "userinfo",
        ),
        (
            https.clone(),
            json!({"method": "oauth-client-credentials", "client_id": "c", "client_secret_env": "S"}),
            "token_url",
        ),
    ];
    for (location, auth, needle) in cases {
        let err = parse_connection(&connection_json(location.clone(), auth.clone()))
            .expect_err(&format!("{location} {auth}"));
        assert!(err.contains(needle), "{needle}: {err}");
    }
    // A literal age identity, and a feed id that isn't <publisher>/<slug>.
    let mut value: Value =
        serde_json::from_slice(&connection_json(https.clone(), none.clone())).unwrap();
    value["age_identity"] = json!("AGE-SECRET-KEY-1INVENTED");
    assert!(parse_connection(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value: Value = serde_json::from_slice(&connection_json(https, none)).unwrap();
    value["feed"] = json!("acme.example");
    assert!(parse_connection(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn connection_reads_oauth_and_pins() {
    let mut value: Value = serde_json::from_slice(&connection_json(
        json!({"kind": "https", "url": "https://feeds.acme.example/track/"}),
        json!({"method": "oauth-client-credentials", "token_url": "https://auth.acme.example/token",
               "client_id": "reader", "client_secret_env": "SECRET", "scope": "feeds:read"}),
    ))
    .unwrap();
    value["keys"] = json!([{ "publisher": "acme.example", "id": "2026-11", "alg": "ed25519",
                             "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg" }]);
    value["age_identity_env"] = json!("AGE_ID");
    let conn = parse_connection(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        conn.auth,
        Auth::OAuth {
            token_url: "https://auth.acme.example/token".to_owned(),
            client_id: "reader".to_owned(),
            client_secret_env: "SECRET".to_owned(),
            resource: None,
            scope: Some("feeds:read".to_owned()),
        }
    );
    assert_eq!(conn.pins.len(), 1);
    assert_eq!(conn.age_identity_env.as_deref(), Some("AGE_ID"));
    assert_eq!(conn.publisher(), "acme.example");
}

// ---- Feeds built in memory, signed with test-only seeds. ----

/// Test-only seeds. Never use them for anything real.
const SEED_A: [u8; 32] = [7; 32];
const SEED_B: [u8; 32] = [8; 32];

fn key_a() -> SigningKey {
    SigningKey::from_seed("acme.example", "a", SEED_A).unwrap()
}

fn key_b() -> SigningKey {
    SigningKey::from_seed("acme.example", "b", SEED_B).unwrap()
}

fn pin(key: &SigningKey) -> Pin {
    let public = key.public();
    Pin {
        publisher: public.publisher,
        id: public.id,
        public_key: public.key,
    }
}

#[derive(Default)]
struct MemSource {
    files: BTreeMap<String, Vec<u8>>,
    etag: Option<String>,
    requests: Vec<String>,
}

impl Source for MemSource {
    fn get(&mut self, path: &str, etag: Option<&str>) -> Result<Fetched, String> {
        self.requests.push(path.to_owned());
        match self.files.get(path) {
            Some(bytes) => {
                if path == "feed.json" && etag.is_some() && etag == self.etag.as_deref() {
                    return Ok(Fetched::NotModified);
                }
                let etag = if path == "feed.json" {
                    self.etag.clone()
                } else {
                    None
                };
                Ok(Fetched::Found {
                    bytes: bytes.clone(),
                    etag,
                })
            }
            None => Ok(Fetched::NotFound),
        }
    }
}

struct Stream<'a> {
    id: &'a str,
    published_at: &'a str,
    signer: Option<&'a SigningKey>,
}

/// A feed of `streams` at `updated_at`, its index signed by `index_signer`.
fn build_feed(
    updated_at: &str,
    streams: &[Stream],
    index_signer: Option<&SigningKey>,
) -> MemSource {
    let mut source = MemSource::default();
    let mut entries = Vec::new();
    for stream in streams {
        let inputs = vec![Input {
            name: "note.json".to_owned(),
            bytes: format!(
                r#"{{"$type":"example.note","version":1,"id":"{}","text":"Invented"}}"#,
                stream.id
            )
            .into_bytes(),
        }];
        let options = PackOptions {
            produced_by: Some(json!({"app": "test"})),
            published_at: Some(stream.published_at.to_owned()),
            feed: Some(("acme.example/track".to_owned(), stream.id.to_owned())),
            signer: stream.signer,
        };
        let zip = pack_with(&inputs, &[], &options).unwrap().zip;
        let sha = sha256_hex(&zip);
        let path = format!("bundles/{sha}.zip");
        entries.push(
            json!({"id": stream.id, "title": "Invented", "record_types": ["example.note"],
                            "bundle": path, "sha256": sha, "published_at": stream.published_at}),
        );
        source.files.insert(path, zip);
    }
    let index = serde_json::to_vec_pretty(&json!({
        "$type": "org.legiblerecords.feed", "version": 1, "id": "acme.example/track",
        "publisher": "acme.example", "audience": "Invented", "updated_at": updated_at,
        "streams": entries,
    }))
    .unwrap();
    if let Some(signer) = index_signer {
        source.files.insert(
            "feed.sig".to_owned(),
            sign(signer, Context::Feed, &index).to_bytes(),
        );
    }
    source.files.insert("feed.json".to_owned(), index);
    source
}

fn conn_with(pins: Vec<Pin>) -> Connection {
    let mut conn = parse_connection(&connection_json(
        json!({"kind": "https", "url": "https://feeds.acme.example/track/"}),
        json!({"method": "none"}),
    ))
    .unwrap();
    conn.pins = pins;
    conn
}

fn key_set_bytes(updated_at: &str, keys: &[&SigningKey]) -> Vec<u8> {
    let keys: Vec<Value> = keys
        .iter()
        .map(|k| {
            json!({"id": k.id, "alg": "ed25519", "public_key": b64url(&k.public().key),
                        "created_at": "2026-11-01T00:00:00Z"})
        })
        .collect();
    serde_json::to_vec(&json!({"$type": "org.legiblerecords.keys", "version": 1,
        "publisher": "acme.example", "updated_at": updated_at, "keys": keys}))
    .unwrap()
}

struct FixedKeys(Result<Option<KeySetFiles>, String>, Vec<String>);

impl KeySource for FixedKeys {
    fn key_set(&mut self, publisher: &str) -> Result<Option<KeySetFiles>, String> {
        self.1.push(publisher.to_owned());
        self.0.clone()
    }
}

fn run(
    source: &mut MemSource,
    keys: &mut dyn KeySource,
    conn: &Connection,
    state: Option<&mut ReaderState>,
) -> PullReport {
    pull(
        source,
        keys,
        conn,
        state,
        &mut |_| Ok(()),
        &PullOptions::default(),
    )
}

#[test]
fn stateless_accepts_rotation_endorsed_by_pinned_key() {
    let (a, b) = (key_a(), key_b());
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: Some(&b),
        }],
        Some(&b),
    );
    let set = key_set_bytes("2026-11-24T00:00:00Z", &[&a, &b]);
    let sig = sign(&a, Context::Keys, &set).to_bytes();
    let mut keys = FixedKeys(Ok(Some((set, Some(sig)))), Vec::new());
    let report = run(&mut source, &mut keys, &conn_with(vec![pin(&a)]), None);
    assert_eq!(keys.1, ["acme.example"]);
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
    assert!(report.pending_keys.is_empty());
    assert!(report.fetch_errors.is_empty(), "{:?}", report.fetch_errors);
}

#[test]
fn unendorsed_rotation_needs_approval_and_keeps_held_set() {
    let (a, b) = (key_a(), key_b());
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: Some(&b),
        }],
        Some(&b),
    );
    let held = KeySet::parse(&key_set_bytes("2026-11-01T00:00:00Z", &[&a])).unwrap();
    let mut state = ReaderState::default();
    state
        .key_sets
        .insert("acme.example".to_owned(), held.clone());
    let before = state.clone();
    let set = key_set_bytes("2026-11-24T00:00:00Z", &[&a, &b]);
    let mut keys = FixedKeys(Ok(Some((set, None))), Vec::new());
    let report = run(&mut source, &mut keys, &conn_with(vec![]), Some(&mut state));
    assert_eq!(report.pending_keys, vec![pin(&b)]);
    // The index is signed by the key waiting for approval.
    assert_eq!(report.index, IndexOutcome::Refused(Code::UnknownKey));
    assert_eq!(state, before);

    // Once a person approves it, the same set is accepted and kept.
    state.approved.push(pin(&b));
    let report = run(&mut source, &mut keys, &conn_with(vec![]), Some(&mut state));
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert!(report.pending_keys.is_empty());
    assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
    assert!(state.key_sets["acme.example"].get("b").is_some());
}

#[test]
fn endorsed_rotation_is_kept_in_state() {
    let (a, b) = (key_a(), key_b());
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: Some(&b),
        }],
        Some(&b),
    );
    let mut state = ReaderState::default();
    state.key_sets.insert(
        "acme.example".to_owned(),
        KeySet::parse(&key_set_bytes("2026-11-01T00:00:00Z", &[&a])).unwrap(),
    );
    let set = key_set_bytes("2026-11-24T00:00:00Z", &[&a, &b]);
    let sig = sign(&a, Context::Keys, &set).to_bytes();
    let mut keys = FixedKeys(Ok(Some((set.clone(), Some(sig)))), Vec::new());
    let report = run(&mut source, &mut keys, &conn_with(vec![]), Some(&mut state));
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(
        state.key_sets["acme.example"].bytes,
        KeySet::parse(&set).unwrap().bytes
    );
    // And it survives a round trip through the state file.
    let again = ReaderState::parse(&state.to_bytes()).unwrap();
    assert!(again.key_sets["acme.example"].get("b").is_some());
}

#[test]
fn rolled_back_key_set_is_a_fetch_error_and_held_set_stays() {
    let a = key_a();
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: Some(&a),
        }],
        Some(&a),
    );
    let mut state = ReaderState::default();
    let held = KeySet::parse(&key_set_bytes("2026-11-24T00:00:00Z", &[&a])).unwrap();
    state
        .key_sets
        .insert("acme.example".to_owned(), held.clone());
    let older = key_set_bytes("2026-11-01T00:00:00Z", &[&a]);
    let mut keys = FixedKeys(Ok(Some((older, None))), Vec::new());
    let report = run(&mut source, &mut keys, &conn_with(vec![]), Some(&mut state));
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
    assert_eq!(report.fetch_errors.len(), 1);
    assert!(
        report.fetch_errors[0].contains("key_set_rollback"),
        "{:?}",
        report.fetch_errors
    );
    assert_eq!(state.key_sets["acme.example"], held);
}

#[test]
fn key_set_for_another_publisher_is_a_fetch_error() {
    let a = key_a();
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: Some(&a),
        }],
        Some(&a),
    );
    let other = SigningKey::from_seed("other.example", "a", SEED_A).unwrap();
    let set = serde_json::to_vec(&json!({"$type": "org.legiblerecords.keys", "version": 1,
        "publisher": "other.example", "updated_at": "2026-11-24T00:00:00Z",
        "keys": [{"id": "a", "alg": "ed25519", "public_key": b64url(&other.public().key),
                  "created_at": "2026-11-01T00:00:00Z"}]}))
    .unwrap();
    let mut keys = FixedKeys(Ok(Some((set, None))), Vec::new());
    let mut state = ReaderState::default();
    let report = run(&mut source, &mut keys, &conn_with(vec![]), Some(&mut state));
    assert_eq!(report.fetch_errors.len(), 1);
    assert!(
        report.fetch_errors[0].contains("other.example"),
        "{:?}",
        report.fetch_errors
    );
    // Nothing trusts acme.example's key, so the signed index names an unknown key.
    assert_eq!(report.index, IndexOutcome::Refused(Code::UnknownKey));
    assert!(state.key_sets.is_empty());
}

#[test]
fn key_source_error_keeps_held_set() {
    let a = key_a();
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: Some(&a),
        }],
        Some(&a),
    );
    let mut state = ReaderState::default();
    state.key_sets.insert(
        "acme.example".to_owned(),
        KeySet::parse(&key_set_bytes("2026-11-01T00:00:00Z", &[&a])).unwrap(),
    );
    let mut keys = FixedKeys(Err("connection refused".to_owned()), Vec::new());
    let report = run(&mut source, &mut keys, &conn_with(vec![]), Some(&mut state));
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
    assert_eq!(report.fetch_errors.len(), 1);
    assert!(report.fetch_errors[0].contains("connection refused"));
}

#[test]
fn unsigned_bundle_from_pinned_publisher_is_refused() {
    let a = key_a();
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[
            Stream {
                id: "signed",
                published_at: "2026-11-24T10:00:00Z",
                signer: Some(&a),
            },
            Stream {
                id: "unsigned",
                published_at: "2026-11-24T10:00:00Z",
                signer: None,
            },
        ],
        Some(&a),
    );
    let report = run(
        &mut source,
        &mut NoKeySource,
        &conn_with(vec![pin(&a)]),
        None,
    );
    assert_eq!(report.streams["signed"], StreamOutcome::Accepted);
    assert_eq!(
        report.streams["unsigned"],
        StreamOutcome::Refused(Code::UnsignedFromPinnedPublisher)
    );
}

#[test]
fn unsigned_feed_from_unpinned_publisher_is_unverified() {
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: None,
        }],
        None,
    );
    let mut delivered = Vec::new();
    let report = pull(
        &mut source,
        &mut NoKeySource,
        &conn_with(vec![]),
        None,
        &mut |d| {
            delivered.push(d.signature);
            Ok(())
        },
        &PullOptions::default(),
    );
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(delivered, vec![SignatureStatus::Unverified]);
}

#[test]
fn index_signed_by_another_publisher_is_refused() {
    let other = SigningKey::from_seed("other.example", "a", SEED_A).unwrap();
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: None,
        }],
        Some(&other),
    );
    let report = run(
        &mut source,
        &mut NoKeySource,
        &conn_with(vec![pin(&other)]),
        None,
    );
    assert_eq!(report.index, IndexOutcome::Refused(Code::PublisherMismatch));
}

#[test]
fn neither_index_is_a_failure() {
    let mut source = MemSource::default();
    let report = run(&mut source, &mut NoKeySource, &conn_with(vec![]), None);
    assert!(matches!(report.index, IndexOutcome::Failed(_)));
    assert!(source.requests.contains(&"feed.json".to_owned()));
    assert!(source.requests.contains(&"feed.json.age".to_owned()));
}

#[test]
fn encrypted_index_needs_age() {
    let mut source = MemSource::default();
    source.files.insert(
        "feed.json.age".to_owned(),
        b"age-encryption.org/v1 invented".to_vec(),
    );
    let report = run(&mut source, &mut NoKeySource, &conn_with(vec![]), None);
    match report.index {
        IndexOutcome::Failed(message) => assert!(message.contains("age"), "{message}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn encrypted_bundle_path_in_plain_feed_is_bad_feed() {
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: None,
        }],
        None,
    );
    let mut index: Value = serde_json::from_slice(&source.files["feed.json"]).unwrap();
    let path = index["streams"][0]["bundle"].as_str().unwrap().to_owned();
    index["streams"][0]["bundle"] = json!(format!("{path}.age"));
    source
        .files
        .insert("feed.json".to_owned(), serde_json::to_vec(&index).unwrap());
    let report = run(&mut source, &mut NoKeySource, &conn_with(vec![]), None);
    assert_eq!(report.index, IndexOutcome::Refused(Code::BadFeed));
}

#[test]
fn etag_skips_an_unchanged_index() {
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: None,
        }],
        None,
    );
    source.etag = Some("\"v1\"".to_owned());
    let mut state = ReaderState::default();
    let report = run(
        &mut source,
        &mut NoKeySource,
        &conn_with(vec![]),
        Some(&mut state),
    );
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(report.etag.as_deref(), Some("\"v1\""));
    let options = PullOptions {
        etag: report.etag.clone(),
        ..PullOptions::default()
    };
    source.requests.clear();
    let report = pull(
        &mut source,
        &mut NoKeySource,
        &conn_with(vec![]),
        Some(&mut state),
        &mut |_| panic!("nothing changed"),
        &options,
    );
    assert_eq!(report.index, IndexOutcome::NotModified);
    assert!(report.streams.is_empty());
    assert!(!source.requests.iter().any(|r| r.starts_with("bundles/")));
}

#[test]
fn bundle_fetch_error_fails_only_that_stream() {
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[
            Stream {
                id: "kept",
                published_at: "2026-11-24T10:00:00Z",
                signer: None,
            },
            Stream {
                id: "lost",
                published_at: "2026-11-24T10:00:00Z",
                signer: None,
            },
        ],
        None,
    );
    let index = parse_feed(&source.files["feed.json"]).unwrap();
    let lost = index.streams.iter().find(|s| s.id == "lost").unwrap();
    source.files.remove(&lost.bundle);
    let mut state = ReaderState::default();
    let report = run(
        &mut source,
        &mut NoKeySource,
        &conn_with(vec![]),
        Some(&mut state),
    );
    assert_eq!(report.streams["kept"], StreamOutcome::Accepted);
    assert!(matches!(report.streams["lost"], StreamOutcome::Failed(_)));
    assert!(state.streams.contains_key("kept"));
    assert!(!state.streams.contains_key("lost"));
}

#[test]
fn parse_feed_refuses_invalid_indexes() {
    let good = json!({"$type": "org.legiblerecords.feed", "version": 1, "id": "acme.example/track",
        "publisher": "acme.example", "audience": "Invented", "updated_at": "2026-11-24T10:00:00Z",
        "streams": [{"id": "notes", "title": "Invented", "record_types": [],
            "bundle": format!("bundles/{}.zip", "0".repeat(64)), "sha256": "0".repeat(64),
            "published_at": "2026-11-24T10:00:00Z"}]});
    assert!(parse_feed(&serde_json::to_vec(&good).unwrap()).is_ok());
    let breakages: [(&str, Value); 6] = [
        ("/version", json!(2)),
        ("/id", json!("acme.example")),
        ("/updated_at", json!("yesterday")),
        ("/streams/0/id", json!("Notes")),
        ("/streams/0/sha256", json!("abc")),
        ("/streams/0/record_types", json!("example.note")),
    ];
    for (pointer, value) in breakages {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            parse_feed(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "{pointer}"
        );
    }
    let mut twice = good.clone();
    let stream = twice["streams"][0].clone();
    twice["streams"].as_array_mut().unwrap().push(stream);
    assert!(parse_feed(&serde_json::to_vec(&twice).unwrap()).is_err());
}

// ---- Review fixes. ----

#[test]
fn served_key_set_makes_unsigned_index_refused_even_before_approval() {
    let a = key_a();
    // A storage attacker strips feed.sig and serves far-future watermarks.
    let mut source = build_feed(
        "2099-01-01T00:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2099-01-01T00:00:00Z",
            signer: None,
        }],
        None,
    );
    let mut state = ReaderState::default();
    let before = state.clone();
    let set = key_set_bytes("2026-11-24T00:00:00Z", &[&a]);
    let mut keys = FixedKeys(Ok(Some((set, None))), Vec::new());
    let report = run(&mut source, &mut keys, &conn_with(vec![]), Some(&mut state));
    assert_eq!(report.pending_keys, vec![pin(&a)]);
    assert_eq!(
        report.index,
        IndexOutcome::Refused(Code::UnsignedFromPinnedPublisher)
    );
    assert!(report.streams.is_empty());
    assert_eq!(state, before);
}

#[test]
fn stateless_report_carries_index_even_when_nothing_is_delivered() {
    let mut source = build_feed(
        "2026-11-24T12:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: None,
        }],
        None,
    );
    // The one remaining stream fails, so nothing is delivered.
    let index = parse_feed(&source.files["feed.json"]).unwrap();
    source.files.remove(&index.streams[0].bundle);
    let report = pull(
        &mut source,
        &mut NoKeySource,
        &conn_with(vec![]),
        None,
        &mut |_| panic!("nothing is delivered"),
        &PullOptions::default(),
    );
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(
        report.index_updated_at.as_deref(),
        Some("2026-11-24T12:00:00Z")
    );
    assert_eq!(report.stream_ids, ["notes"]);

    // An index that withdraws everything still reports its date.
    let mut empty = build_feed("2026-11-24T13:00:00Z", &[], None);
    let report = run(&mut empty, &mut NoKeySource, &conn_with(vec![]), None);
    assert_eq!(
        report.index_updated_at.as_deref(),
        Some("2026-11-24T13:00:00Z")
    );
    assert!(report.stream_ids.is_empty());
}

#[test]
fn refused_index_carries_no_index_fields() {
    let (_, conn, state) = load_case("stale-index");
    let mut state = state.unwrap();
    let mut source = DirSource {
        root: format!("{}/stale-index/feed", vectors_dir()).into(),
    };
    let report = pull(
        &mut source,
        &mut NoKeySource,
        &conn,
        Some(&mut state),
        &mut |_| Ok(()),
        &PullOptions::default(),
    );
    assert_eq!(report.index_updated_at, None);
    assert!(report.stream_ids.is_empty());
}

#[test]
fn connection_urls_are_https_with_a_slash() {
    let none = json!({"method": "none"});
    let refused = [
        ("http://feeds.acme.example/track/", "https"),
        ("http://127.0.0.2/track/", "https"),
        ("https://feeds.acme.example/track", "slash"),
        ("https://feeds.acme.example/track/?x=1", "slash"),
        ("https://feeds.acme.example//track/", "//"),
        ("https://feeds.acme.example/track//", "//"),
    ];
    for (url, needle) in refused {
        let err = parse_connection(&connection_json(
            json!({"kind": "https", "url": url}),
            none.clone(),
        ))
        .expect_err(url);
        assert!(err.contains(needle), "{url}: {err}");
    }
    for url in [
        "https://feeds.acme.example/track/",
        "http://127.0.0.1:8080/feed/",
        "http://localhost/",
        "http://[::1]:9000/feed/",
    ] {
        parse_connection(&connection_json(
            json!({"kind": "https", "url": url}),
            none.clone(),
        ))
        .unwrap_or_else(|e| panic!("{url}: {e}"));
    }
    let err = parse_connection(&connection_json(
        json!({"kind": "s3", "endpoint": "http://storage.acme.example", "region": "auto",
               "bucket": "b", "prefix": ""}),
        json!({"method": "s3", "access_key_id_env": "K", "secret_access_key_env": "S"}),
    ))
    .unwrap_err();
    assert!(err.contains("https"), "{err}");
}

#[test]
fn not_modified_echoes_the_etag() {
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: None,
        }],
        None,
    );
    source.etag = Some("\"v1\"".to_owned());
    let options = PullOptions {
        etag: Some("\"v1\"".to_owned()),
        ..PullOptions::default()
    };
    let report = pull(
        &mut source,
        &mut NoKeySource,
        &conn_with(vec![]),
        None,
        &mut |_| panic!("nothing changed"),
        &options,
    );
    assert_eq!(report.index, IndexOutcome::NotModified);
    assert_eq!(report.etag.as_deref(), Some("\"v1\""));
}

#[test]
fn stale_index_with_endorsed_rotation_leaves_whole_state() {
    let (a, b) = (key_a(), key_b());
    let mut source = build_feed(
        "2026-11-24T09:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T09:00:00Z",
            signer: Some(&a),
        }],
        Some(&a),
    );
    let mut state = ReaderState {
        feed_updated_at: Some("2026-11-24T10:00:00Z".to_owned()),
        ..ReaderState::default()
    };
    state.key_sets.insert(
        "acme.example".to_owned(),
        KeySet::parse(&key_set_bytes("2026-11-01T00:00:00Z", &[&a])).unwrap(),
    );
    let before = state.clone();
    let set = key_set_bytes("2026-11-24T00:00:00Z", &[&a, &b]);
    let sig = sign(&a, Context::Keys, &set).to_bytes();
    let mut keys = FixedKeys(Ok(Some((set, Some(sig)))), Vec::new());
    let report = run(&mut source, &mut keys, &conn_with(vec![]), Some(&mut state));
    assert_eq!(report.index, IndexOutcome::Refused(Code::StaleFeed));
    assert!(report.fetch_errors.is_empty(), "{:?}", report.fetch_errors);
    assert_eq!(state, before);
}

#[test]
fn partly_approved_key_set_is_not_accepted() {
    let (a, b) = (key_a(), key_b());
    let c = SigningKey::from_seed("acme.example", "c", [9; 32]).unwrap();
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: Some(&a),
        }],
        Some(&a),
    );
    let mut state = ReaderState::default();
    state.key_sets.insert(
        "acme.example".to_owned(),
        KeySet::parse(&key_set_bytes("2026-11-01T00:00:00Z", &[&a])).unwrap(),
    );
    state.approved.push(pin(&b));
    let held = state.key_sets["acme.example"].clone();
    let set = key_set_bytes("2026-11-24T00:00:00Z", &[&a, &b, &c]);
    let mut keys = FixedKeys(Ok(Some((set, None))), Vec::new());
    let report = run(&mut source, &mut keys, &conn_with(vec![]), Some(&mut state));
    assert_eq!(report.pending_keys, vec![pin(&c)]);
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(state.key_sets["acme.example"], held);
}
