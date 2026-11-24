//! Feeds: the spec's feed vectors, connection files, reader state and `pull`.

use std::collections::BTreeMap;

use legible_records::bundle::{pack_with, sha256_hex, Input, PackOptions, SignatureStatus};
use legible_records::code::Code;
use legible_records::feed::{
    parse_connection, parse_feed, pull, Auth, Connection, Delivered, DirSource, Fetched,
    IndexOutcome, KeySetFiles, KeySetOutcome, KeySource, Location, NoKeySource, PullOptions,
    PullReport, ReaderState, Signer, Source, StreamOutcome, StreamState,
};
use legible_records::keys::{KeySet, Pin};
use legible_records::sign::{b64url, sign, Context, SigningKey};
use legible_records::time;
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

/// What a vector's publisher serves at `/.well-known/legible-records/`:
/// the case's `key-set/`, or nothing when it has none.
struct VectorKeys(std::path::PathBuf);

impl KeySource for VectorKeys {
    fn key_set(&mut self, publisher: &str) -> Result<Option<KeySetFiles>, String> {
        assert_eq!(
            publisher, "acme.example",
            "the reader asks for the feed's publisher"
        );
        let Ok(keys) = std::fs::read(self.0.join("keys.json")) else {
            return Ok(None);
        };
        Ok(Some((keys, std::fs::read(self.0.join("keys.sig")).ok())))
    }
}

/// The key set outcome a poll reports, as the vectors write it.
fn key_set_str(outcome: &KeySetOutcome) -> String {
    match outcome {
        KeySetOutcome::Accepted => "accepted".to_owned(),
        KeySetOutcome::Pending(_) => "needs_approval".to_owned(),
        KeySetOutcome::Refused(code) => code.as_str().to_owned(),
        KeySetOutcome::NotServed => "not served".to_owned(),
        KeySetOutcome::Failed(e) => format!("failed: {e}"),
    }
}

/// Vectors this reader doesn't pass yet; each must still fail, so the list
/// only shrinks.
const PENDING: &[&str] = &[];

#[test]
fn feed_vectors() {
    let (mut count, mut failures) = (0, Vec::new());
    for entry in std::fs::read_dir(vectors_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let (case, conn, mut state) = load_case(&name);
        let mut source = DirSource {
            root: path.join("feed"),
        };
        let served = path.join("key-set");
        let now = case["now"].as_str().unwrap_or("2026-12-01T00:00:00Z");
        let options = PullOptions {
            now: Some(time::parse(now).unwrap()),
            ..PullOptions::default()
        };
        let report = pull(
            &mut source,
            &mut VectorKeys(served.clone()),
            &conn,
            state.as_mut(),
            &mut |_| Ok(()),
            &options,
        );
        let streams: BTreeMap<String, Value> = report
            .streams
            .iter()
            .map(|(id, o)| (id.clone(), json!(stream_str(o))))
            .collect();
        let mut got = json!({"index": index_str(&report.index), "streams": streams});
        if served.is_dir() {
            got["key_set"] = json!(key_set_str(&report.key_set));
        }
        // The state the poll leaves, when the case expects one: in the
        // vectors' form, without the on-disk $type and version.
        if let (Some(_), Some(state)) = (case["expect"].get("state"), &state) {
            let mut value: Value = serde_json::from_slice(&state.to_bytes()).unwrap();
            let object = value.as_object_mut().unwrap();
            object.remove("$type");
            object.remove("version");
            got["state"] = value;
        }
        let expect = &case["expect"];
        match (&got == expect, PENDING.contains(&name.as_str())) {
            (false, false) => {
                failures.push(format!("{name}:\n  expected {expect}\n  got      {got}"))
            }
            (true, true) => failures.push(format!("{name}: passes; take it off PENDING")),
            _ => {}
        }
        count += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
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
            sha256: Some(entry.sha256.clone()),
            published_at: entry.published_at.clone(),
            signer: Some(Signer {
                publisher: "acme.example".to_owned(),
                key: "2026-11".to_owned(),
            }),
        }
    );
    assert_eq!(
        state.feed_updated_at.as_deref(),
        Some(index.updated_at.as_str())
    );
    assert_eq!(
        state.feed_signer,
        Some(Signer {
            publisher: "acme.example".to_owned(),
            key: "2026-11".to_owned(),
        })
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
        alg: "ed25519".to_owned(),
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
    pull(source, keys, conn, state, &mut |_| Ok(()), &options())
}

/// The reader's clock in these tests, as in the vectors.
fn options() -> PullOptions<'static> {
    PullOptions {
        now: Some(time::parse("2026-12-01T00:00:00Z").unwrap()),
        ..PullOptions::default()
    }
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
    assert_eq!(report.key_set, KeySetOutcome::Accepted);
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
    assert_eq!(report.key_set, KeySetOutcome::Pending(vec![pin(&b)]));
    // The index is signed by the key waiting for approval.
    assert_eq!(report.index, IndexOutcome::Refused(Code::UnknownKey));
    assert_eq!(state, before);

    // Once a person approves it, the same set is accepted and kept.
    state.approved.push(pin(&b));
    let report = run(&mut source, &mut keys, &conn_with(vec![]), Some(&mut state));
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(report.key_set, KeySetOutcome::Accepted);
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
fn rolled_back_key_set_is_refused_and_held_set_stays() {
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
    assert_eq!(report.key_set, KeySetOutcome::Refused(Code::KeySetRollback));
    assert_eq!(state.key_sets["acme.example"], held);
}

#[test]
fn key_set_for_another_publisher_is_bad_key_set() {
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
    assert_eq!(report.key_set, KeySetOutcome::Refused(Code::BadKeySet));
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
    assert!(
        matches!(&report.key_set, KeySetOutcome::Failed(e) if e.contains("connection refused")),
        "{:?}",
        report.key_set
    );
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
    assert_eq!(report.key_set, KeySetOutcome::Pending(vec![pin(&a)]));
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
        ("http://128.0.0.1/track/", "https"),
        ("http://127.0.0.256/track/", "https"),
        ("http://127.example/track/", "https"),
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
        "http://127.0.0.2/feed/",
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
fn stale_index_with_endorsed_rotation_keeps_only_the_key_set() {
    // The key steps run whatever happens to the index: an accepted key set
    // is held from then on, and nothing else changes.
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
    let set = key_set_bytes("2026-11-24T00:00:00Z", &[&a, &b]);
    let sig = sign(&a, Context::Keys, &set).to_bytes();
    let mut keys = FixedKeys(Ok(Some((set.clone(), Some(sig)))), Vec::new());
    let mut expected = state.clone();
    expected
        .key_sets
        .insert("acme.example".to_owned(), KeySet::parse(&set).unwrap());
    let report = run(&mut source, &mut keys, &conn_with(vec![]), Some(&mut state));
    assert_eq!(report.index, IndexOutcome::Refused(Code::StaleFeed));
    assert_eq!(report.key_set, KeySetOutcome::Accepted);
    assert_eq!(state, expected);
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
    assert_eq!(report.key_set, KeySetOutcome::Pending(vec![pin(&c)]));
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(state.key_sets["acme.example"], held);
}

/// A key set of `keys`, with `revoked` marked revoked.
fn key_set_revoking(updated_at: &str, keys: &[&SigningKey], revoked: &SigningKey) -> Vec<u8> {
    let keys: Vec<Value> = keys
        .iter()
        .map(|k| {
            let mut entry = json!({"id": k.id, "alg": "ed25519",
                "public_key": b64url(&k.public().key), "created_at": "2026-11-01T00:00:00Z"});
            if k.id == revoked.id {
                entry["revoked_at"] = json!("2026-11-20T00:00:00Z");
            }
            entry
        })
        .collect();
    serde_json::to_vec(&json!({"$type": "org.legiblerecords.keys", "version": 1,
        "publisher": "acme.example", "updated_at": updated_at, "keys": keys}))
    .unwrap()
}

#[test]
fn revocation_counts_in_a_set_its_own_key_endorses() {
    // R1: a stateless reader pins K; the publisher serves a set that revokes
    // K, signed by K. The endorsement is bad, but the revocation still
    // counts: what K signs is revoked_key.
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
    let set = key_set_revoking("2026-11-24T00:00:00Z", &[&a], &a);
    let sig = sign(&a, Context::Keys, &set).to_bytes();
    let mut keys = FixedKeys(Ok(Some((set, Some(sig)))), Vec::new());
    let report = run(&mut source, &mut keys, &conn_with(vec![pin(&a)]), None);
    assert_eq!(report.key_set, KeySetOutcome::Refused(Code::BadEndorsement));
    assert_eq!(report.index, IndexOutcome::Refused(Code::RevokedKey));

    // And a bundle K signed, checked on its own against the same trust.
    let bundle = pack_with(
        &[Input {
            name: "note.json".to_owned(),
            bytes: br#"{"$type":"example.note","version":1,"id":"n"}"#.to_vec(),
        }],
        &[],
        &PackOptions {
            signer: Some(&a),
            ..PackOptions::default()
        },
    )
    .unwrap();
    let opened = legible_records::bundle::open(&bundle.zip, Default::default()).unwrap();
    let mut trust = legible_records::keys::Trust {
        pins: vec![pin(&a)],
        ..Default::default()
    };
    trust
        .revoking
        .push(KeySet::parse(&key_set_revoking("2026-11-24T00:00:00Z", &[&a], &a)).unwrap());
    assert_eq!(
        legible_records::bundle::check_signature(&opened, &trust, Some("acme.example")),
        Err(Code::RevokedKey)
    );
}

#[test]
fn a_rolled_back_set_that_passes_parsing_still_revokes() {
    // R1 again, with state: the served set is refused as a rollback, yet the
    // key it revokes is revoked on this poll. It isn't held, so it clears
    // nothing: the stream a signed keeps its state, and a's new bundle for
    // it is refused.
    let (a, b) = (key_a(), key_b());
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[
            Stream {
                id: "old",
                published_at: "2026-11-24T10:00:00Z",
                signer: Some(&a),
            },
            Stream {
                id: "notes",
                published_at: "2026-11-24T10:00:00Z",
                signer: Some(&b),
            },
        ],
        Some(&b),
    );
    let mut state = ReaderState::default();
    state.key_sets.insert(
        "acme.example".to_owned(),
        KeySet::parse(&key_set_bytes("2026-11-24T00:00:00Z", &[&a, &b])).unwrap(),
    );
    state.streams.insert(
        "old".to_owned(),
        StreamState {
            sha256: Some("0".repeat(64)),
            published_at: "2026-11-23T00:00:00Z".to_owned(),
            signer: Some(Signer {
                publisher: "acme.example".to_owned(),
                key: "a".to_owned(),
            }),
        },
    );
    let older = key_set_revoking("2026-11-01T00:00:00Z", &[&a, &b], &a);
    let mut keys = FixedKeys(Ok(Some((older, None))), Vec::new());
    let report = run(&mut source, &mut keys, &conn_with(vec![]), Some(&mut state));
    assert_eq!(report.key_set, KeySetOutcome::Refused(Code::KeySetRollback));
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(
        report.streams["old"],
        StreamOutcome::Refused(Code::RevokedKey)
    );
    assert_eq!(state.streams["old"].sha256, Some("0".repeat(64)));
    assert_eq!(state.streams["old"].published_at, "2026-11-23T00:00:00Z");
    assert!(state.streams["old"].signer.is_some());
    assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
    // The revocation is reported, as from a set that isn't held.
    assert_eq!(report.revocations.len(), 1);
    assert_eq!(report.revocations[0].id, "a");
    assert!(!report.revocations[0].held);
    // The held set isn't replaced.
    assert!(state.key_sets["acme.example"]
        .get("a")
        .is_some_and(|k| k.revoked_at.is_none()));
}

#[test]
fn revocation_reaches_a_reader_whose_index_is_unchanged() {
    // The key set is fetched before the index, so a revocation is honoured
    // on a poll that would have been a 304; the ETag isn't sent, the index
    // is fetched whole, and the forgotten stream is reported.
    let (a, b) = (key_a(), key_b());
    let mut source = build_feed(
        "2026-11-24T10:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: Some(&a),
        }],
        Some(&b),
    );
    source.etag = Some("\"v1\"".to_owned());
    let mut state = ReaderState::default();
    state.key_sets.insert(
        "acme.example".to_owned(),
        KeySet::parse(&key_set_bytes("2026-11-01T00:00:00Z", &[&a, &b])).unwrap(),
    );
    let report = run(
        &mut source,
        &mut NoKeySource,
        &conn_with(vec![]),
        Some(&mut state),
    );
    assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
    assert_eq!(report.etag.as_deref(), Some("\"v1\""));
    let revoking = key_set_revoking("2026-11-24T00:00:00Z", &[&a, &b], &a);
    let mut keys = FixedKeys(Ok(Some((revoking, None))), Vec::new());
    let options = PullOptions {
        etag: report.etag.clone(),
        ..options()
    };
    source.requests.clear();
    let mut delivered = 0;
    let report = pull(
        &mut source,
        &mut keys,
        &conn_with(vec![]),
        Some(&mut state),
        &mut |_| {
            delivered += 1;
            Ok(())
        },
        &options,
    );
    assert_eq!(report.key_set, KeySetOutcome::Accepted);
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(
        report.streams["notes"],
        StreamOutcome::Refused(Code::RevokedKey)
    );
    assert_eq!(delivered, 0);
    assert_eq!(report.etag, None);
    // Cleared: fetched anew next poll, with its published_at kept as the floor.
    assert_eq!(
        state.streams["notes"],
        StreamState {
            sha256: None,
            published_at: "2026-11-24T10:00:00Z".to_owned(),
            signer: None,
        }
    );
    assert!(report.revocations.iter().any(|r| r.id == "a" && r.held));
    // The index (signed by b) was accepted, so its watermark stands.
    assert_eq!(
        state.feed_signer,
        Some(Signer {
            publisher: "acme.example".to_owned(),
            key: "b".to_owned()
        })
    );
}

#[test]
fn state_files_without_signers_are_still_read() {
    let old = br#"{"$type":"legible-reader-state","version":1,
        "feed_updated_at":"2026-11-24T10:00:00Z",
        "streams":{"notes":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000",
                            "published_at":"2026-11-24T10:00:00Z"}},
        "key_sets":{},
        "approved":[{"publisher":"acme.example","id":"a","public_key":"6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"}]}"#;
    let state = ReaderState::parse(old).unwrap();
    assert_eq!(state.feed_signer, None);
    assert_eq!(state.streams["notes"].signer, None);
    assert_eq!(state.approved[0].alg, "ed25519");
    // Written back, it has the new fields.
    let value: Value = serde_json::from_slice(&state.to_bytes()).unwrap();
    assert_eq!(value["feed_signer"], Value::Null);
    assert_eq!(value["streams"]["notes"]["signer"], Value::Null);
    assert_eq!(value["approved"][0]["alg"], "ed25519");
}

#[test]
fn bad_feed_says_why() {
    let mut source = build_feed(
        "2026-12-03T00:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T10:00:00Z",
            signer: None,
        }],
        None,
    );
    let report = run(&mut source, &mut NoKeySource, &conn_with(vec![]), None);
    assert_eq!(report.index, IndexOutcome::Refused(Code::BadFeed));
    assert!(
        report
            .index_detail
            .as_deref()
            .is_some_and(|d| d.contains("24 hours")),
        "{:?}",
        report.index_detail
    );
}

// ---- N1: a revocation in a key set the reader doesn't hold. ----

/// A key source that serves, poll by poll, the next key set in its script.
struct ScriptedKeys(std::collections::VecDeque<KeySetFiles>);

impl KeySource for ScriptedKeys {
    fn key_set(&mut self, publisher: &str) -> Result<Option<KeySetFiles>, String> {
        assert_eq!(publisher, "acme.example");
        Ok(Some(self.0.pop_front().expect("a key set for every poll")))
    }
}

/// A directory of its own under the system's temp directory, removed when dropped.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!("legible-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    /// Replaces what the directory holds with `source`'s files.
    fn serve(&self, source: &MemSource) {
        let _ = std::fs::remove_dir_all(&self.0);
        for (path, bytes) in &source.files {
            let file = self.0.join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, bytes).unwrap();
        }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn unheld_revocation_cannot_reopen_replay() {
    // The reader holds a's key set and has accepted a feed a signed at 10:00.
    // Poll 1: whoever controls the server serves an unsigned set that adds a
    // key and revokes a. It waits for approval, so it isn't held: what a
    // signed is refused on this poll, and the reader's state doesn't move.
    // Poll 2: the genuine set again, with an older index and bundles that a
    // really signed. The watermark and floors still refuse them.
    let (a, b) = (key_a(), key_b());
    let genuine = key_set_bytes("2026-11-24T00:00:00Z", &[&a]);
    let attack = key_set_revoking("2026-11-24T00:00:00Z", &[&a, &b], &a);
    let current = build_feed(
        "2026-11-24T10:00:00Z",
        &[
            Stream {
                id: "notes",
                published_at: "2026-11-24T10:00:00Z",
                signer: Some(&a),
            },
            Stream {
                id: "reports",
                published_at: "2026-11-24T10:00:00Z",
                signer: Some(&a),
            },
        ],
        Some(&a),
    );
    let old = build_feed(
        "2026-11-24T09:00:00Z",
        &[Stream {
            id: "notes",
            published_at: "2026-11-24T09:00:00Z",
            signer: Some(&a),
        }],
        Some(&a),
    );
    let dir = TempDir::new("n1-attack");
    dir.serve(&current);
    let mut source = DirSource {
        root: dir.0.clone(),
    };
    let mut keys = ScriptedKeys(
        [(genuine.clone(), None), (attack, None), (genuine, None)]
            .into_iter()
            .collect(),
    );
    let conn = conn_with(vec![]);
    let mut state = ReaderState::default();
    let mut delivered = Vec::new();
    let mut poll = |state: &mut ReaderState, source: &mut DirSource| {
        pull(
            source,
            &mut keys,
            &conn,
            Some(state),
            &mut |d| {
                delivered.push((d.stream.id.clone(), d.published_at.clone()));
                Ok(())
            },
            &options(),
        )
    };

    // Poll 0: the genuine feed is accepted; the set adds a, so it needs
    // approval unless pinned. Approve a so the set is accepted and held.
    state.approved.push(pin(&a));
    let report = poll(&mut state, &mut source);
    assert_eq!(report.key_set, KeySetOutcome::Accepted);
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
    let accepted = state.clone();

    // Poll 1: the pending set.
    let first = poll(&mut state, &mut source);
    let after_first = state.clone();
    // Poll 2: the genuine set, and old content a really signed.
    dir.serve(&old);
    let second = poll(&mut state, &mut source);

    // The old content is refused: the watermark is still there.
    assert_eq!(second.key_set, KeySetOutcome::Accepted);
    assert_eq!(
        second.index,
        IndexOutcome::Refused(Code::StaleFeed),
        "{:?}",
        second.streams
    );
    assert!(second.streams.is_empty(), "{:?}", second.streams);
    assert_eq!(state, accepted);
    // On poll 1 the pending set's revocation refused a's index, and changed
    // nothing the reader keeps.
    assert!(matches!(first.key_set, KeySetOutcome::Pending(_)));
    assert_eq!(first.index, IndexOutcome::Refused(Code::RevokedKey));
    assert!(first.streams.is_empty(), "{:?}", first.streams);
    assert_eq!(after_first, accepted);
    assert_eq!(
        delivered,
        [
            ("notes".to_owned(), "2026-11-24T10:00:00Z".to_owned()),
            ("reports".to_owned(), "2026-11-24T10:00:00Z".to_owned()),
        ]
    );
}

#[test]
fn deliveries_say_which_revocations_are_held() {
    // A stateless reader pins a and b. The publisher serves a set that revokes b:
    // with no new key it is accepted, so the revocation is held, and a
    // destination clears what b signed. With a new key as well, it waits
    // for approval: the revocation still refuses b on this poll, but is not
    // held, and a destination changes nothing for it.
    let (a, b) = (key_a(), key_b());
    let feed = || {
        build_feed(
            "2026-11-24T10:00:00Z",
            &[Stream {
                id: "notes",
                published_at: "2026-11-24T10:00:00Z",
                signer: Some(&a),
            }],
            Some(&a),
        )
    };
    let c = SigningKey::from_seed("acme.example", "c", [9; 32]).unwrap();
    for (keys, held) in [(vec![&a, &b], true), (vec![&a, &b, &c], false)] {
        let set = key_set_revoking("2026-11-24T00:00:00Z", &keys, &b);
        let mut served = FixedKeys(Ok(Some((set, None))), Vec::new());
        let mut revocations = Vec::new();
        let report = pull(
            &mut feed(),
            &mut served,
            &conn_with(vec![pin(&a), pin(&b)]),
            None,
            &mut |d| {
                revocations = d.revocations;
                Ok(())
            },
            &options(),
        );
        assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
        assert_eq!(report.revocations, revocations);
        assert_eq!(revocations.len(), 1, "{revocations:?}");
        assert_eq!(revocations[0].id, "b");
        assert_eq!(revocations[0].public_key, b.public().key);
        assert_eq!(revocations[0].held, held);
    }
}

// ---- A pin a key set lists under another id (feeds.md § Trust). ----

/// A key set for acme.example listing each `(id, key, revoked)`.
fn key_set_with_ids(updated_at: &str, keys: &[(&str, &SigningKey, bool)]) -> Vec<u8> {
    let keys: Vec<Value> = keys
        .iter()
        .map(|(id, k, revoked)| {
            let mut entry = json!({"id": id, "alg": "ed25519",
                "public_key": b64url(&k.public().key), "created_at": "2026-11-01T00:00:00Z"});
            if *revoked {
                entry["revoked_at"] = json!("2026-11-20T00:00:00Z");
            }
            entry
        })
        .collect();
    serde_json::to_vec(&json!({"$type": "org.legiblerecords.keys", "version": 1,
        "publisher": "acme.example", "updated_at": updated_at, "keys": keys}))
    .unwrap()
}

fn one_stream_feed(updated_at: &str, signer: &SigningKey) -> MemSource {
    build_feed(
        updated_at,
        &[Stream {
            id: "notes",
            published_at: updated_at,
            signer: Some(signer),
        }],
        Some(signer),
    )
}

#[test]
fn stateful_pin_alias_in_held_set_is_unknown_key() {
    // The connection pins a's bytes as "a"; the held set lists them as "a-b".
    let a = key_a();
    let set = key_set_with_ids("2026-11-24T00:00:00Z", &[("a-b", &a, false)]);
    let mut state = ReaderState::default();
    state
        .key_sets
        .insert("acme.example".to_owned(), KeySet::parse(&set).unwrap());
    let before = state.clone();
    let report = run(
        &mut one_stream_feed("2026-11-24T10:00:00Z", &a),
        &mut NoKeySource,
        &conn_with(vec![pin(&a)]),
        Some(&mut state),
    );
    assert_eq!(report.index, IndexOutcome::Refused(Code::UnknownKey));
    assert!(report.streams.is_empty(), "{:?}", report.streams);
    assert_eq!(state, before);
}

#[test]
fn stateless_pin_alias_in_served_set_is_unknown_key() {
    // A stateless reader pins a as "a"; the publisher serves, unendorsed, a
    // set listing a's bytes as "a-b". It waits for approval, and still the
    // pin no longer counts.
    let a = key_a();
    let set = key_set_with_ids("2026-11-24T00:00:00Z", &[("a-b", &a, false)]);
    let mut keys = FixedKeys(Ok(Some((set, None))), Vec::new());
    let report = run(
        &mut one_stream_feed("2026-11-24T10:00:00Z", &a),
        &mut keys,
        &conn_with(vec![pin(&a)]),
        None,
    );
    assert!(matches!(report.key_set, KeySetOutcome::Pending(_)));
    assert_eq!(report.index, IndexOutcome::Refused(Code::UnknownKey));
    assert!(report.streams.is_empty(), "{:?}", report.streams);
}

#[test]
fn stateless_destination_matches_a_revocation_by_bytes() {
    // A stateless reader pins a as "a" and c as "c". Poll 1: no key set; a
    // signs. The destination keeps the signer with its public key. Poll 2:
    // the publisher's set, endorsed by c, lists a's bytes as "a-old",
    // revoked. The revocation names "a-old", not "a", so only the bytes
    // link it to what the destination holds.
    let a = key_a();
    let c = SigningKey::from_seed("acme.example", "c", [9; 32]).unwrap();
    let conn = conn_with(vec![pin(&a), pin(&c)]);
    let mut held: Vec<(String, String, String, [u8; 32])> = Vec::new();
    let report = pull(
        &mut one_stream_feed("2026-11-24T10:00:00Z", &a),
        &mut FixedKeys(Ok(None), Vec::new()),
        &conn,
        None,
        &mut |d| {
            let SignatureStatus::Verified {
                publisher,
                key,
                public_key,
            } = d.signature
            else {
                panic!("signed by a: {:?}", d.signature);
            };
            held.push((d.stream.id.clone(), publisher, key, public_key));
            Ok(())
        },
        &options(),
    );
    assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
    assert_eq!(
        held,
        [(
            "notes".to_owned(),
            "acme.example".to_owned(),
            "a".to_owned(),
            a.public().key
        )]
    );

    let set = key_set_with_ids(
        "2026-11-25T00:00:00Z",
        &[("c", &c, false), ("a-old", &a, true)],
    );
    let sig = sign(&c, Context::Keys, &set).to_bytes();
    let mut revocations = Vec::new();
    let report = pull(
        &mut one_stream_feed("2026-11-25T10:00:00Z", &c),
        &mut FixedKeys(Ok(Some((set, Some(sig)))), Vec::new()),
        &conn,
        None,
        &mut |d| {
            revocations = d.revocations;
            Ok(())
        },
        &options(),
    );
    assert_eq!(report.key_set, KeySetOutcome::Accepted);
    assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
    assert_eq!(report.revocations, revocations);
    assert_eq!(revocations.len(), 1, "{revocations:?}");
    let r = &revocations[0];
    assert!(r.held);
    assert_eq!(
        (r.publisher.as_str(), r.id.as_str()),
        ("acme.example", "a-old")
    );
    // By id the destination would miss it; by bytes it clears what a signed.
    let (_, publisher, key, public_key) = &held[0];
    assert!(!(r.publisher == *publisher && r.id == *key));
    assert!(r.publisher == *publisher && r.public_key == *public_key);
}
