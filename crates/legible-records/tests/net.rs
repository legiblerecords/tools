//! Network sources: HTTPS (none, bearer, OAuth client credentials), S3, and
//! publishers' key sets, against a local HTTP server on 127.0.0.1.
//!
//! The S3 test against a real server runs when `LEGIBLE_TEST_S3_ENDPOINT` is
//! set (CI starts SeaweedFS and always sets it).
#![cfg(feature = "net")]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use legible_records::bundle::{pack_with, sha256_hex, Input, Limits, PackOptions};
use legible_records::feed::{
    parse_connection, pull, Connection, Fetched, IndexOutcome, KeySetOutcome, KeySource,
    NoKeySource, PullOptions, PullReport, ReaderState, Source, StreamOutcome,
};
use legible_records::keys::KeySet;
use legible_records::net::{source, source_with_limits, HttpsKeySource, MAX_INDEX_BYTES};
use legible_records::sign::{b64url, sign, Context, SigningKey};
use serde_json::{json, Value};

// ---- A local HTTP server that logs every request. ----

#[derive(Clone, Debug)]
struct Req {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn path(&self) -> &str {
        self.url.split('?').next().unwrap_or_default()
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Sent without a Content-Length.
    chunked: bool,
}

impl Reply {
    fn status(status: u16) -> Reply {
        Reply {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            chunked: false,
        }
    }

    fn ok(body: Vec<u8>) -> Reply {
        Reply {
            body,
            ..Reply::status(200)
        }
    }

    fn header(mut self, name: &str, value: &str) -> Reply {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

type Handler = dyn Fn(&Req) -> Reply + Send + Sync;

struct Server {
    /// `http://127.0.0.1:<port>`, no slash.
    origin: String,
    log: Arc<Mutex<Vec<Req>>>,
}

impl Server {
    fn requests(&self) -> Vec<Req> {
        self.log.lock().unwrap().clone()
    }

    fn count(&self, method: &str, path: &str) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.method == method && r.path() == path)
            .count()
    }
}

fn serve(handler: impl Fn(&Req) -> Reply + Send + Sync + 'static) -> Server {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let thread_log = Arc::clone(&log);
    let handler: Box<Handler> = Box::new(handler);
    std::thread::spawn(move || {
        for mut request in server.incoming_requests() {
            let mut body = String::new();
            let _ = request.as_reader().read_to_string(&mut body);
            let req = Req {
                method: request.method().as_str().to_owned(),
                url: request.url().to_owned(),
                headers: request
                    .headers()
                    .iter()
                    .map(|h| {
                        (
                            h.field.as_str().as_str().to_owned(),
                            h.value.as_str().to_owned(),
                        )
                    })
                    .collect(),
                body,
            };
            thread_log.lock().unwrap().push(req.clone());
            let reply = handler(&req);
            let headers: Vec<tiny_http::Header> = reply
                .headers
                .iter()
                .map(|(k, v)| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap())
                .collect();
            let length = (!reply.chunked).then_some(reply.body.len());
            let response = tiny_http::Response::new(
                tiny_http::StatusCode(reply.status),
                headers,
                std::io::Cursor::new(reply.body),
                length,
                None,
            );
            let _ = request.respond(response);
        }
    });
    Server {
        origin: format!("http://127.0.0.1:{port}"),
        log,
    }
}

/// Serves `files` under `/track/`, 404 for anything else.
fn files_handler(files: BTreeMap<String, Vec<u8>>) -> impl Fn(&Req) -> Reply + Send + Sync {
    move |req| match req
        .path()
        .strip_prefix("/track/")
        .and_then(|p| files.get(p))
    {
        Some(bytes) => Reply::ok(bytes.clone()),
        None => Reply::status(404),
    }
}

// ---- Feeds, signed with test-only seeds. ----

/// Test-only seed. Never use it for anything real.
const SEED_A: [u8; 32] = [7; 32];

fn key_a() -> SigningKey {
    SigningKey::from_seed("acme.example", "a", SEED_A).unwrap()
}

/// A feed of `streams` (id, published_at), each bundle and the index signed
/// by `signer` when given.
fn build_feed(streams: &[(&str, &str)], signer: Option<&SigningKey>) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut entries = Vec::new();
    for (id, published_at) in streams {
        let inputs = vec![Input {
            name: "note.json".to_owned(),
            bytes: format!(
                r#"{{"$type":"example.note","version":1,"id":"{id}","text":"Invented"}}"#
            )
            .into_bytes(),
        }];
        let options = PackOptions {
            produced_by: Some(json!({"app": "test"})),
            published_at: Some((*published_at).to_owned()),
            feed: Some(("acme.example/track".to_owned(), (*id).to_owned())),
            signer,
            ..PackOptions::default()
        };
        let zip = pack_with(&inputs, &[], &options).unwrap().zip;
        let sha = sha256_hex(&zip);
        let path = format!("bundles/{sha}.zip");
        entries.push(
            json!({"id": id, "title": "Invented", "record_types": ["example.note"],
            "bundle": path, "sha256": sha, "published_at": published_at}),
        );
        files.insert(path, zip);
    }
    let index = serde_json::to_vec_pretty(&json!({
        "$type": "org.legiblerecords.feed", "version": 1, "id": "acme.example/track",
        "publisher": "acme.example", "audience": "Invented",
        "updated_at": "2026-11-24T10:00:00Z", "streams": entries,
    }))
    .unwrap();
    if let Some(signer) = signer {
        files.insert(
            "feed.sig".to_owned(),
            sign(signer, Context::Feed, &index).to_bytes(),
        );
    }
    files.insert("feed.json".to_owned(), index);
    files
}

fn key_set_bytes(keys: &[&SigningKey]) -> Vec<u8> {
    let keys: Vec<Value> = keys
        .iter()
        .map(|k| {
            json!({"id": k.id, "alg": "ed25519", "public_key": b64url(&k.public().key),
                "created_at": "2026-11-01T00:00:00Z"})
        })
        .collect();
    serde_json::to_vec(&json!({"$type": "org.legiblerecords.keys", "version": 1,
        "publisher": "acme.example", "updated_at": "2026-11-01T00:00:00Z", "keys": keys}))
    .unwrap()
}

fn connection(location: Value, auth: Value) -> Connection {
    parse_connection(
        &serde_json::to_vec(&json!({
            "$type": "org.legiblerecords.feed-connection", "version": 1,
            "feed": "acme.example/track", "location": location, "auth": auth,
        }))
        .unwrap(),
    )
    .unwrap()
}

fn https_connection(server: &Server, auth: Value) -> Connection {
    connection(
        json!({"kind": "https", "url": format!("{}/track/", server.origin)}),
        auth,
    )
}

fn env_with(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: BTreeMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |name| map.get(name).cloned()
}

fn no_env(_: &str) -> Option<String> {
    None
}

fn run(
    source: &mut dyn Source,
    keys: &mut dyn KeySource,
    conn: &Connection,
    state: Option<&mut ReaderState>,
    etag: Option<String>,
) -> PullReport {
    pull(
        source,
        keys,
        conn,
        state,
        &mut |_| Ok(()),
        &PullOptions {
            etag,
            ..PullOptions::default()
        },
    )
}

// ---- HTTPS ----

#[test]
fn bearer_header_sent() {
    let files = build_feed(&[("notes", "2026-11-24T10:00:00Z")], None);
    let serve_files = files_handler(files);
    let server = serve(move |req| {
        if req.header("Authorization") != Some("Bearer invented-token") {
            return Reply::status(401);
        }
        serve_files(req)
    });
    let conn = https_connection(
        &server,
        json!({"method": "bearer", "token_env": "FEED_TOKEN"}),
    );
    let mut src = source(&conn, &env_with(&[("FEED_TOKEN", "invented-token")])).unwrap();
    let report = run(&mut *src, &mut NoKeySource, &conn, None, None);
    assert_eq!(report.index, IndexOutcome::Accepted, "{report:?}");
    assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
    let requests = server.requests();
    assert!(requests.len() >= 4, "{requests:?}");
    assert!(requests
        .iter()
        .all(|r| r.header("Authorization") == Some("Bearer invented-token")));
}

#[test]
fn bearer_token_variable_must_be_set() {
    let server = serve(|_| Reply::status(404));
    let conn = https_connection(
        &server,
        json!({"method": "bearer", "token_env": "FEED_TOKEN"}),
    );
    let e = source(&conn, &no_env).err().expect("refused");
    assert!(e.contains("FEED_TOKEN"), "{e}");
}

#[test]
fn errors_never_carry_the_token() {
    let server = serve(|_| Reply::status(500));
    let conn = https_connection(
        &server,
        json!({"method": "bearer", "token_env": "FEED_TOKEN"}),
    );
    let mut src = source(&conn, &env_with(&[("FEED_TOKEN", "invented-token")])).unwrap();
    let e = src.get("feed.json", None).unwrap_err();
    assert!(e.contains("500"), "{e}");
    assert!(!e.contains("invented-token"), "{e}");
}

/// A token server that hands out `tok-1`, `tok-2`, ... with `expires_in`,
/// and a feed that wants the latest one.
fn oauth_server(expires_in: u64) -> Server {
    let files = build_feed(&[("notes", "2026-11-24T10:00:00Z")], None);
    let serve_files = files_handler(files);
    let issued = Arc::new(Mutex::new(0u32));
    serve(move |req| {
        if req.path() == "/token" {
            if req.method != "POST" {
                return Reply::status(405);
            }
            let mut n = issued.lock().unwrap();
            *n += 1;
            let body = json!({"access_token": format!("tok-{n}"), "token_type": "Bearer",
                "expires_in": expires_in});
            return Reply::ok(serde_json::to_vec(&body).unwrap())
                .header("Content-Type", "application/json");
        }
        let latest = format!("Bearer tok-{}", issued.lock().unwrap());
        if req.header("Authorization") != Some(latest.as_str()) {
            return Reply::status(401);
        }
        serve_files(req)
    })
}

fn oauth_connection(server: &Server) -> Connection {
    https_connection(
        server,
        json!({"method": "oauth-client-credentials",
            "token_url": format!("{}/token", server.origin),
            "client_id": "reader", "client_secret_env": "FEED_SECRET",
            "resource": "https://feeds.acme.example/", "scope": "feed.read"}),
    )
}

#[test]
fn oauth_token_fetched_once_and_reused() {
    let server = oauth_server(3600);
    let conn = oauth_connection(&server);
    let mut src = source(&conn, &env_with(&[("FEED_SECRET", "invented-secret")])).unwrap();
    let first = run(&mut *src, &mut NoKeySource, &conn, None, None);
    assert_eq!(first.streams["notes"], StreamOutcome::Accepted, "{first:?}");
    let second = run(&mut *src, &mut NoKeySource, &conn, None, None);
    assert_eq!(
        second.streams["notes"],
        StreamOutcome::Accepted,
        "{second:?}"
    );
    assert_eq!(server.count("POST", "/token"), 1);

    let token_request = server
        .requests()
        .into_iter()
        .find(|r| r.path() == "/token")
        .unwrap();
    assert!(token_request
        .header("Content-Type")
        .unwrap()
        .starts_with("application/x-www-form-urlencoded"));
    let form: BTreeMap<String, String> = token_request
        .body
        .split('&')
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap();
            (k.to_owned(), url_decode(v))
        })
        .collect();
    assert_eq!(form["grant_type"], "client_credentials");
    assert_eq!(form["client_id"], "reader");
    assert_eq!(form["client_secret"], "invented-secret");
    assert_eq!(form["resource"], "https://feeds.acme.example/");
    assert_eq!(form["scope"], "feed.read");
}

fn url_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap()
}

#[test]
fn oauth_token_refetched_when_expiring() {
    // Good for 4 s: the margin is half that (it is 60 s for tokens good for
    // two minutes or more), so it is fetched again two seconds on.
    let server = oauth_server(4);
    let conn = oauth_connection(&server);
    let mut src = source(&conn, &env_with(&[("FEED_SECRET", "invented-secret")])).unwrap();
    let first = run(&mut *src, &mut NoKeySource, &conn, None, None);
    assert_eq!(first.streams["notes"], StreamOutcome::Accepted, "{first:?}");
    assert_eq!(server.count("POST", "/token"), 1);
    std::thread::sleep(Duration::from_millis(2100));
    let second = run(&mut *src, &mut NoKeySource, &conn, None, None);
    assert_eq!(
        second.streams["notes"],
        StreamOutcome::Accepted,
        "{second:?}"
    );
    assert_eq!(server.count("POST", "/token"), 2);
}

#[test]
fn short_lived_oauth_token_is_reused_within_half_its_life() {
    // Good for 10 s, less than the 60 s margin: still reused, not fetched
    // again for every request.
    let server = oauth_server(10);
    let conn = oauth_connection(&server);
    let mut src = source(&conn, &env_with(&[("FEED_SECRET", "invented-secret")])).unwrap();
    for _ in 0..2 {
        let report = run(&mut *src, &mut NoKeySource, &conn, None, None);
        assert_eq!(
            report.streams["notes"],
            StreamOutcome::Accepted,
            "{report:?}"
        );
    }
    assert_eq!(server.count("POST", "/token"), 1);
}

#[test]
fn oauth_huge_expires_in_does_not_panic() {
    // u64::MAX seconds can't be added to an Instant: held with no expiry.
    let server = oauth_server(u64::MAX);
    let conn = oauth_connection(&server);
    let mut src = source(&conn, &env_with(&[("FEED_SECRET", "invented-secret")])).unwrap();
    for _ in 0..2 {
        let report = run(&mut *src, &mut NoKeySource, &conn, None, None);
        assert_eq!(
            report.streams["notes"],
            StreamOutcome::Accepted,
            "{report:?}"
        );
    }
    assert_eq!(server.count("POST", "/token"), 1);
}

#[test]
fn redirect_drops_authorization() {
    let target = serve(|_| Reply::ok(b"{}".to_vec()));
    let location = format!("{}/track/feed.json", target.origin);
    let origin = serve(move |_| Reply::status(302).header("Location", &location));
    let conn = https_connection(
        &origin,
        json!({"method": "bearer", "token_env": "FEED_TOKEN"}),
    );
    let mut src = source(&conn, &env_with(&[("FEED_TOKEN", "invented-token")])).unwrap();
    assert_eq!(
        src.get("feed.json", None).unwrap(),
        Fetched::Found {
            bytes: b"{}".to_vec(),
            etag: None
        }
    );
    assert_eq!(
        origin.requests()[0].header("Authorization"),
        Some("Bearer invented-token")
    );
    let followed = target.requests();
    assert_eq!(followed.len(), 1);
    assert_eq!(followed[0].header("Authorization"), None);
}

#[test]
fn token_request_does_not_follow_redirects() {
    let target =
        serve(|_| Reply::ok(br#"{"access_token":"stolen","token_type":"Bearer"}"#.to_vec()));
    let location = format!("{}/token", target.origin);
    let token_server = serve(move |_| Reply::status(307).header("Location", &location));
    let conn = https_connection(
        &token_server,
        json!({"method": "oauth-client-credentials",
            "token_url": format!("{}/token", token_server.origin),
            "client_id": "reader", "client_secret_env": "FEED_SECRET"}),
    );
    let mut src = source(&conn, &env_with(&[("FEED_SECRET", "invented-secret")])).unwrap();
    let e = src.get("feed.json", None).unwrap_err();
    assert!(e.contains("307"), "{e}");
    assert!(!e.contains("invented-secret"), "{e}");
    assert_eq!(token_server.count("POST", "/token"), 1);
    assert!(target.requests().is_empty(), "{:?}", target.requests());
}

#[test]
fn oauth_token_errors_do_not_echo_the_secret() {
    // A 200 without an access_token, and a 400 whose body repeats the
    // secret: both are errors that say neither the secret nor the body.
    let replies: [(u16, &[u8]); 2] = [
        (200, br#"{"error":"invalid_client"}"#),
        (400, b"invented-secret was wrong"),
    ];
    for (status, body) in replies {
        let server = serve(move |req| {
            if req.path() == "/token" {
                Reply {
                    status,
                    ..Reply::ok(body.to_vec())
                }
            } else {
                Reply::status(404)
            }
        });
        let conn = oauth_connection(&server);
        let mut src = source(&conn, &env_with(&[("FEED_SECRET", "invented-secret")])).unwrap();
        let e = src.get("feed.json", None).unwrap_err();
        assert!(e.contains("token"), "{e}");
        assert!(!e.contains("invented-secret"), "{e}");
        if status == 400 {
            assert!(e.contains("400"), "{e}");
        }
        assert_eq!(server.count("GET", "/track/feed.json"), 0);
    }
}

#[test]
fn oauth_token_refetched_after_401() {
    // The feed refuses the first token: it is dropped and a new one asked for.
    let files = build_feed(&[("notes", "2026-11-24T10:00:00Z")], None);
    let serve_files = files_handler(files);
    let issued = Arc::new(Mutex::new(0u32));
    let server = serve(move |req| {
        if req.path() == "/token" {
            let mut n = issued.lock().unwrap();
            *n += 1;
            let body = json!({"access_token": format!("tok-{n}"), "token_type": "bearer",
                "expires_in": 3600});
            return Reply::ok(serde_json::to_vec(&body).unwrap());
        }
        if req.header("Authorization") != Some("Bearer tok-2") {
            return Reply::status(401);
        }
        serve_files(req)
    });
    let conn = oauth_connection(&server);
    let mut src = source(&conn, &env_with(&[("FEED_SECRET", "invented-secret")])).unwrap();
    let report = run(&mut *src, &mut NoKeySource, &conn, None, None);
    assert_eq!(
        report.streams["notes"],
        StreamOutcome::Accepted,
        "{report:?}"
    );
    assert_eq!(server.count("POST", "/token"), 2);
}

#[test]
fn etag_round_trip_quoted() {
    let files = build_feed(&[("notes", "2026-11-24T10:00:00Z")], None);
    let serve_files = files_handler(files);
    let server = serve(move |req| {
        if req.path() == "/track/feed.json" {
            if req.header("If-None-Match") == Some("\"abc\"") {
                return Reply::status(304).header("ETag", "\"abc\"");
            }
            return serve_files(req).header("ETag", "\"abc\"");
        }
        serve_files(req)
    });
    let conn = https_connection(&server, json!({"method": "none"}));
    let mut src = source(&conn, &no_env).unwrap();
    let mut state = ReaderState::default();
    let first = run(&mut *src, &mut NoKeySource, &conn, Some(&mut state), None);
    assert_eq!(first.index, IndexOutcome::Accepted, "{first:?}");
    assert_eq!(first.etag.as_deref(), Some("\"abc\""));

    let second = run(
        &mut *src,
        &mut NoKeySource,
        &conn,
        Some(&mut state),
        first.etag.clone(),
    );
    assert_eq!(second.index, IndexOutcome::NotModified, "{second:?}");
    let last = server
        .requests()
        .into_iter()
        .rev()
        .find(|r| r.path() == "/track/feed.json")
        .unwrap();
    assert_eq!(last.header("If-None-Match"), Some("\"abc\""));
    // A weak ETag goes back exactly as given too.
    let weak = serve(|req| {
        assert_eq!(req.header("If-None-Match"), Some("W/\"x y\""));
        Reply::status(304)
    });
    let conn = https_connection(&weak, json!({"method": "none"}));
    let mut src = source(&conn, &no_env).unwrap();
    assert_eq!(
        src.get("feed.json", Some("W/\"x y\"")).unwrap(),
        Fetched::NotModified
    );
}

#[test]
fn bundle_404_mid_poll_fails_one_stream() {
    let mut files = build_feed(
        &[
            ("kept", "2026-11-24T10:00:00Z"),
            ("lost", "2026-11-24T10:00:00Z"),
        ],
        None,
    );
    let index = legible_records::feed::parse_feed(&files["feed.json"]).unwrap();
    let lost = index.streams.iter().find(|s| s.id == "lost").unwrap();
    files.remove(&lost.bundle);
    let server = serve(files_handler(files));
    let conn = https_connection(&server, json!({"method": "none"}));
    let mut src = source(&conn, &no_env).unwrap();
    let mut state = ReaderState::default();
    let report = run(&mut *src, &mut NoKeySource, &conn, Some(&mut state), None);
    assert_eq!(report.index, IndexOutcome::Accepted);
    assert_eq!(report.streams["kept"], StreamOutcome::Accepted);
    assert!(
        matches!(&report.streams["lost"], StreamOutcome::Failed(e) if e.contains("not found")),
        "{report:?}"
    );
    assert!(state.streams.contains_key("kept"));
    assert!(!state.streams.contains_key("lost"));
    assert_eq!(report.etag, None);
}

#[test]
fn paths_join_with_one_slash() {
    let server = serve(|_| Reply::status(404));
    let conn = https_connection(&server, json!({"method": "none"}));
    let mut src = source(&conn, &no_env).unwrap();
    assert_eq!(src.get("feed.json", None).unwrap(), Fetched::NotFound);
    assert_eq!(src.get("bundles/x.zip", None).unwrap(), Fetched::NotFound);
    let paths: Vec<String> = server.requests().iter().map(|r| r.url.clone()).collect();
    assert_eq!(paths, ["/track/feed.json", "/track/bundles/x.zip"]);
    assert!(src.get("../escape", None).is_err());
    assert!(src.get("/feed.json", None).is_err());
}

// ---- Size caps ----

#[test]
fn oversized_index_refused() {
    let big = vec![b' '; MAX_INDEX_BYTES as usize + 1];
    for chunked in [false, true] {
        let big = big.clone();
        let server = serve(move |req| {
            if req.path() == "/track/feed.json" {
                Reply {
                    chunked,
                    ..Reply::ok(big.clone())
                }
            } else {
                Reply::status(404)
            }
        });
        let conn = https_connection(&server, json!({"method": "none"}));
        let mut src = source(&conn, &no_env).unwrap();
        let report = run(&mut *src, &mut NoKeySource, &conn, None, None);
        assert!(
            matches!(&report.index, IndexOutcome::Failed(e) if e.contains("feed.json") && e.contains(&MAX_INDEX_BYTES.to_string())),
            "chunked {chunked}: {:?}",
            report.index
        );
    }
    // Exactly the cap is fine.
    let exact = vec![b' '; MAX_INDEX_BYTES as usize];
    let server = serve(move |_| Reply::ok(exact.clone()));
    let conn = https_connection(&server, json!({"method": "none"}));
    let mut src = source(&conn, &no_env).unwrap();
    assert!(matches!(
        src.get("feed.json", None),
        Ok(Fetched::Found { .. })
    ));
}

#[test]
fn bundle_capped_at_limits() {
    let files = build_feed(&[("notes", "2026-11-24T10:00:00Z")], None);
    let server = serve(files_handler(files.clone()));
    let conn = https_connection(&server, json!({"method": "none"}));
    let bundle = files.keys().find(|p| p.starts_with("bundles/")).unwrap();
    let limits = Limits {
        max_files: 10,
        max_total_bytes: 10,
    };
    // A bundle may hold up to its limits' total, and its zip and age
    // framing on top; this one is far past that.
    let big = vec![0u8; limits.max_stored_bytes() as usize + 1];
    let big_server = serve(move |_| Reply {
        chunked: true,
        ..Reply::ok(big.clone())
    });
    let big_conn = https_connection(&big_server, json!({"method": "none"}));
    let mut src = source_with_limits(&big_conn, &no_env, &limits).unwrap();
    let e = src.get(bundle, None).unwrap_err();
    assert!(e.contains(&limits.max_stored_bytes().to_string()), "{e}");
    // The index cap doesn't apply to bundles.
    let mut src = source(&conn, &no_env).unwrap();
    assert!(matches!(src.get(bundle, None), Ok(Fetched::Found { .. })));
}

// ---- Key sets ----

/// Serves `keys.json` and `keys.sig` under the well-known path.
fn key_server(keys_json: Reply, keys_sig: Reply) -> Server {
    let keys_json = Mutex::new(Some(keys_json));
    let keys_sig = Mutex::new(Some(keys_sig));
    serve(move |req| {
        let slot = match req.path() {
            "/.well-known/legible-records/keys.json" => &keys_json,
            "/.well-known/legible-records/keys.sig" => &keys_sig,
            _ => return Reply::status(404),
        };
        slot.lock().unwrap().take().unwrap_or(Reply::status(500))
    })
}

#[test]
fn key_source_fetches_set_and_sig() {
    let set = key_set_bytes(&[&key_a()]);
    let sig = sign(&key_a(), Context::Keys, &set).to_bytes();
    let server = key_server(Reply::ok(set.clone()), Reply::ok(sig.clone()));
    let mut keys = HttpsKeySource::with_base(&server.origin).unwrap();
    assert_eq!(
        keys.key_set("acme.example").unwrap(),
        Some((set.clone(), Some(sig)))
    );

    let server = key_server(Reply::ok(set.clone()), Reply::status(404));
    let mut keys = HttpsKeySource::with_base(&server.origin).unwrap();
    assert_eq!(keys.key_set("acme.example").unwrap(), Some((set, None)));

    let server = key_server(Reply::status(404), Reply::status(404));
    let mut keys = HttpsKeySource::with_base(&server.origin).unwrap();
    assert_eq!(keys.key_set("acme.example").unwrap(), None);
    assert_eq!(
        server.count("GET", "/.well-known/legible-records/keys.sig"),
        0
    );

    // Not a domain: refused before anything is fetched.
    let mut keys = HttpsKeySource::with_base(&server.origin).unwrap();
    assert!(keys.key_set("acme.example/evil?").is_err());

    let big = vec![b' '; MAX_INDEX_BYTES as usize + 1];
    let server = key_server(Reply::ok(big), Reply::status(404));
    let mut keys = HttpsKeySource::with_base(&server.origin).unwrap();
    assert!(keys.key_set("acme.example").is_err());
}

#[test]
fn key_set_unreachable_uses_cache() {
    let a = key_a();
    let feed = serve(files_handler(build_feed(
        &[("notes", "2026-11-24T10:00:00Z")],
        Some(&a),
    )));
    let keys_server = key_server(Reply::status(500), Reply::status(500));
    let conn = https_connection(&feed, json!({"method": "none"}));
    let mut state = ReaderState::default();
    let held = KeySet::parse(&key_set_bytes(&[&a])).unwrap();
    state
        .key_sets
        .insert("acme.example".to_owned(), held.clone());
    let mut src = source(&conn, &no_env).unwrap();
    let mut keys = HttpsKeySource::with_base(&keys_server.origin).unwrap();
    let report = run(&mut *src, &mut keys, &conn, Some(&mut state), None);
    assert_eq!(report.index, IndexOutcome::Accepted, "{report:?}");
    assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
    assert!(
        matches!(&report.key_set, KeySetOutcome::Failed(e) if e.contains("500")),
        "{:?}",
        report.key_set
    );
    // No downgrade: the held set is still the one held.
    assert_eq!(state.key_sets["acme.example"], held);
}

#[test]
fn key_set_unreachable_with_nothing_else_fails_the_poll() {
    // A 403 or a 5xx on keys.json can't make a signing publisher look like
    // one with no key set: with no pin, approval or held set, the poll fails.
    let a = key_a();
    for status in [403, 500] {
        let feed = serve(files_handler(build_feed(
            &[("notes", "2026-11-24T10:00:00Z")],
            Some(&a),
        )));
        let keys_server = key_server(Reply::status(status), Reply::status(404));
        let conn = https_connection(&feed, json!({"method": "none"}));
        let mut state = ReaderState::default();
        let mut src = source(&conn, &no_env).unwrap();
        let mut keys = HttpsKeySource::with_base(&keys_server.origin).unwrap();
        let report = run(&mut *src, &mut keys, &conn, Some(&mut state), None);
        assert!(
            matches!(&report.index, IndexOutcome::Failed(e) if e.contains("key set")),
            "{status}: {:?}",
            report.index
        );
        assert!(
            matches!(&report.key_set, KeySetOutcome::Failed(e) if e.contains(&status.to_string())),
            "{status}: {:?}",
            report.key_set
        );
        assert!(report.streams.is_empty());
        assert_eq!(state, ReaderState::default());
        // The feed itself wasn't read.
        assert_eq!(feed.count("GET", "/feed.json"), 0, "{status}");
    }
}

#[test]
fn key_set_unreachable_with_a_pin_checks_with_the_pin() {
    let a = key_a();
    let feed = serve(files_handler(build_feed(
        &[("notes", "2026-11-24T10:00:00Z")],
        Some(&a),
    )));
    let keys_server = key_server(Reply::status(403), Reply::status(404));
    let mut conn = https_connection(&feed, json!({"method": "none"}));
    conn.pins = vec![legible_records::keys::Pin {
        publisher: "acme.example".to_owned(),
        id: "a".to_owned(),
        alg: "ed25519".to_owned(),
        public_key: a.public().key,
    }];
    let mut src = source(&conn, &no_env).unwrap();
    let mut keys = HttpsKeySource::with_base(&keys_server.origin).unwrap();
    let report = run(&mut *src, &mut keys, &conn, None, None);
    assert_eq!(report.index, IndexOutcome::Accepted, "{report:?}");
    assert_eq!(report.streams["notes"], StreamOutcome::Accepted);
    assert!(matches!(report.key_set, KeySetOutcome::Failed(_)));
}

// ---- S3 ----

fn s3_connection(endpoint: &str, bucket: &str, prefix: &str) -> Connection {
    connection(
        json!({"kind": "s3", "endpoint": endpoint, "region": "us-east-1", "bucket": bucket,
            "prefix": prefix, "path_style": true}),
        json!({"method": "s3", "access_key_id_env": "S3_KEY", "secret_access_key_env": "S3_SECRET"}),
    )
}

/// Without a real S3 server: both spellings of the prefix ask for the same
/// object, signed, with nothing secret in an error.
#[test]
fn s3_prefix_slash_normalized_locally() {
    let server = serve(|req| {
        if req.path() == "/acme-legible/feeds/track/feed.json" {
            Reply::ok(b"{}".to_vec()).header("ETag", "\"e1\"")
        } else {
            Reply::status(500)
        }
    });
    let env = env_with(&[("S3_KEY", "invented-key"), ("S3_SECRET", "invented-secret")]);
    for prefix in [
        "feeds/track",
        "feeds/track/",
        "feeds/track//",
        "/feeds/track/",
    ] {
        let conn = s3_connection(&server.origin, "acme-legible", prefix);
        let mut src = source(&conn, &env).unwrap();
        assert_eq!(
            src.get("feed.json", Some("\"e0\"")).unwrap(),
            Fetched::Found {
                bytes: b"{}".to_vec(),
                etag: Some("\"e1\"".to_owned())
            },
            "prefix {prefix:?}"
        );
        let e = src.get("feed.sig", None).unwrap_err();
        assert!(e.contains("500"), "{e}");
        assert!(!e.contains("X-Amz") && !e.contains("invented"), "{e}");
    }
    let requests = server.requests();
    let gets: Vec<&Req> = requests
        .iter()
        .filter(|r| r.path().ends_with("feed.json"))
        .collect();
    assert_eq!(gets.len(), 4);
    for get in gets {
        assert!(get.url.contains("X-Amz-Signature="), "{}", get.url);
        assert!(get.url.contains("X-Amz-Expires=60"), "{}", get.url);
        assert!(get.url.contains("invented-key"), "{}", get.url);
        assert_eq!(get.header("If-None-Match"), Some("\"e0\""));
    }
    // An empty prefix stays empty.
    let conn = s3_connection(&server.origin, "acme-legible", "");
    let mut src = source(&conn, &env).unwrap();
    let _ = src.get("feed.json", None);
    assert_eq!(
        server.requests().last().unwrap().path(),
        "/acme-legible/feed.json"
    );
}

#[test]
fn s3_403_says_the_key_may_not_list() {
    let server = serve(|_| Reply::status(403));
    let env = env_with(&[("S3_KEY", "invented-key"), ("S3_SECRET", "invented-secret")]);
    let conn = s3_connection(&server.origin, "acme-legible", "feeds/track");
    let mut src = source(&conn, &env).unwrap();
    let e = src.get("feed.json.age", None).unwrap_err();
    assert_eq!(
        e,
        "HTTP 403 (not authorized; S3 also answers 403 for a missing object when the key can't list the bucket)"
    );
    // An https feed's 403 has no S3 hint.
    let conn = https_connection(&server, json!({"method": "none"}));
    let e = source(&conn, &no_env)
        .unwrap()
        .get("feed.json", None)
        .unwrap_err();
    assert_eq!(e, "HTTP 403 (not authorized)");
}

#[test]
fn key_source_origin_must_be_a_url() {
    assert!(HttpsKeySource::with_base("not a url").is_err());
}

#[test]
fn s3_needs_its_credentials() {
    let conn = s3_connection("http://127.0.0.1:9", "acme-legible", "feeds/track");
    let e = source(&conn, &env_with(&[("S3_KEY", "k")]))
        .err()
        .expect("refused");
    assert!(e.contains("S3_SECRET"), "{e}");
    // S3 auth on an HTTPS location, or bearer on S3, is refused.
    let conn = connection(
        json!({"kind": "https", "url": "https://feeds.acme.example/track/"}),
        json!({"method": "s3", "access_key_id_env": "S3_KEY", "secret_access_key_env": "S3_SECRET"}),
    );
    assert!(source(&conn, &env_with(&[("S3_KEY", "k"), ("S3_SECRET", "s")])).is_err());
    let conn = connection(
        json!({"kind": "s3", "endpoint": "https://storage.acme.example", "region": "auto",
            "bucket": "b", "prefix": "p"}),
        json!({"method": "bearer", "token_env": "T"}),
    );
    assert!(source(&conn, &env_with(&[("T", "t")])).is_err());
}

/// Against a real S3 server (SeaweedFS in CI): a feed uploaded under
/// `feeds/track/` reads through either spelling of the prefix.
#[test]
fn s3_prefix_slash_normalized() {
    let Ok(endpoint) = std::env::var("LEGIBLE_TEST_S3_ENDPOINT") else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI must set LEGIBLE_TEST_S3_ENDPOINT so that the S3 test runs"
        );
        eprintln!("s3_prefix_slash_normalized: LEGIBLE_TEST_S3_ENDPOINT is not set; not run");
        return;
    };
    let key = std::env::var("LEGIBLE_TEST_S3_ACCESS_KEY").unwrap_or_else(|_| "test".to_owned());
    let secret =
        std::env::var("LEGIBLE_TEST_S3_SECRET_KEY").unwrap_or_else(|_| "testtesttest".to_owned());
    let run_id = format!(
        "run-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    // The bucket LEGIBLE_TEST_S3_BUCKET names already exists (CI's
    // SeaweedFS makes it); without one, the test makes its own.
    let given = std::env::var("LEGIBLE_TEST_S3_BUCKET").ok();
    let name = given
        .clone()
        .unwrap_or_else(|| format!("legible-test-{run_id}"));
    let bucket = rusty_s3::Bucket::new(
        url::Url::parse(&endpoint).unwrap(),
        rusty_s3::UrlStyle::Path,
        name.clone(),
        "us-east-1",
    )
    .unwrap();
    let creds = rusty_s3::Credentials::new(key.clone(), secret.clone());
    let agent: ureq::Agent = ureq::Agent::config_builder().proxy(None).build().into();
    use rusty_s3::S3Action;
    if given.is_none() {
        let url = bucket.create_bucket(&creds).sign(Duration::from_secs(60));
        agent.put(url.as_str()).send_empty().expect("create bucket");
    }
    // Each run has its own prefix, so runs against one bucket don't meet.
    let base = format!("{run_id}/feeds/track");
    let a = key_a();
    for (path, bytes) in build_feed(&[("notes", "2026-11-24T10:00:00Z")], Some(&a)) {
        let url = bucket
            .put_object(Some(&creds), &format!("{base}/{path}"))
            .sign(Duration::from_secs(60));
        agent.put(url.as_str()).send(&bytes[..]).expect("upload");
    }
    // A wrong secret is refused: the server really checks the signature.
    let wrong = env_with(&[("S3_KEY", &key), ("S3_SECRET", "not-the-secret")]);
    let conn = s3_connection(&endpoint, &name, &base);
    let e = source(&conn, &wrong)
        .unwrap()
        .get("feed.json", None)
        .unwrap_err();
    eprintln!("s3: wrong secret: {e}");
    assert!(e.contains("403"), "{e}");
    let env = env_with(&[("S3_KEY", &key), ("S3_SECRET", &secret)]);
    // A missing object, to a key that may list the bucket, is a 404.
    let missing = source(&conn, &env).unwrap().get("feed.json.age", None);
    eprintln!("s3: missing object: {missing:?}");
    assert_eq!(missing, Ok(Fetched::NotFound));
    for prefix in [base.clone(), format!("{base}/")] {
        let mut conn = s3_connection(&endpoint, &name, &prefix);
        conn.pins = vec![legible_records::keys::Pin {
            publisher: "acme.example".to_owned(),
            id: "a".to_owned(),
            alg: "ed25519".to_owned(),
            public_key: a.public().key,
        }];
        let mut src = source(&conn, &env).unwrap();
        let report = run(&mut *src, &mut NoKeySource, &conn, None, None);
        assert_eq!(
            report.index,
            IndexOutcome::Accepted,
            "{prefix:?}: {report:?}"
        );
        assert_eq!(
            report.streams["notes"],
            StreamOutcome::Accepted,
            "{prefix:?}"
        );
        assert!(report.etag.is_some(), "S3 gives an ETag");
        // And the ETag comes back as NotModified.
        let again = run(
            &mut *src,
            &mut NoKeySource,
            &conn,
            None,
            report.etag.clone(),
        );
        assert_eq!(again.index, IndexOutcome::NotModified, "{prefix:?}");
        eprintln!(
            "s3: prefix {prefix:?}: index accepted, notes accepted, ETag {:?}, then not modified",
            report.etag
        );
    }
}
