//! `legible feed publish` (`spec/feeds.md` § Publishing): pack records into
//! a bundle, write it into a feed's directory, and update the feed index and
//! its signature.
//!
//! The writes go in the spec's order, each by temp file and rename in its own
//! directory: the bundle, then `feed.json` (or `.age`), then `feed.sig`.
//! Between the last two a reader can see the new index with the old
//! `feed.sig`: it gets `bad_signature` and polls again.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Subcommand};
use legible_records::bundle::{self, Input, PackOptions};
use legible_records::bundle::{Limits, SignatureStatus};
use legible_records::feed::index::{is_feed_id, is_sha256, is_slug};
use legible_records::feed::{
    check_bundle_paths, collectable, next_published_at, parse_connection, parse_feed, pull,
    render_feed, Connection, Feed, IndexOutcome, KeySource, PublishState, PullOptions, PullReport,
    ReaderState, StreamEntry, StreamOutcome, MAX_INDEX_BYTES,
};
use legible_records::net::{source_with_limits, HttpsKeySource};
use legible_records::sign::{self, is_publisher, Context, SigningKey};
use legible_records::time::{self, Instant};
use serde_json::Value;

use crate::Stop;

#[derive(Subcommand)]
pub enum FeedCommand {
    /// Publish a stream of a feed into a directory laid out as the feed's base URL: pack the
    /// inputs into a signed (with -k) bundle, write bundles/<sha256>.zip, then feed.json and
    /// feed.sig. A feed is plain, or encrypted when -r is given, never both. Never deploys:
    /// it writes only the directory given.
    Publish(PublishArgs),
    /// Poll a feed from a connection file and report each stream's outcome, without keeping
    /// anything: nothing is written or delivered. Exit 0 when everything is accepted, 1 when
    /// anything is refused or a key waits for approval, 2 when the feed couldn't be reached.
    Check(ReadArgs),
    /// Poll a feed from a connection file, write each accepted bundle (decrypted) to
    /// <out>/<stream>/<published_at>.zip, and keep what the reader remembers in --state.
    Pull(PullArgs),
}

#[derive(Args)]
pub struct ReadArgs {
    /// The connection file.
    connection: PathBuf,
    /// Read publishers' key sets from this origin instead of their own domains (for tests).
    #[arg(long, hide = true, value_name = "ORIGIN")]
    key_origin: Option<String>,
}

#[derive(Args)]
pub struct PullArgs {
    /// The connection file.
    connection: PathBuf,
    /// The directory for the reader's state: <feed id with / as __>.json in it.
    #[arg(long)]
    state: PathBuf,
    /// The directory accepted bundles are written to, as <stream>/<published_at>.zip.
    #[arg(long)]
    out: PathBuf,
    /// Approve a key a key set adds without an endorsement, as the pull printed it:
    /// <publisher>/<id>=<public_key>. Kept in the state; repeat for several.
    #[arg(long, value_name = "PUBLISHER/ID=PUBLIC_KEY")]
    approve: Vec<String>,
    #[arg(long, hide = true, value_name = "ORIGIN")]
    key_origin: Option<String>,
}

#[derive(Args)]
pub struct PublishArgs {
    /// The feed's directory (what is served at its base URL). Created if it isn't there.
    dir: PathBuf,
    /// The feed's id, <publisher>/<slug>, such as acme.example/track.
    #[arg(long)]
    feed: String,
    /// Who the feed is for, for people to read.
    #[arg(long)]
    audience: String,
    /// The stream's id, a slug unique in the feed.
    #[arg(long)]
    stream: String,
    /// The stream's title, for people.
    #[arg(long)]
    title: String,
    /// A $type the stream carries; repeat for several. Defaults to the $types found in the inputs.
    #[arg(long = "record-type", value_name = "TYPE")]
    record_types: Vec<String>,
    /// The publisher's domain. Taken from the key when -k is given; required without one.
    #[arg(long)]
    publisher: Option<String>,
    /// The secret key (from `keys new`) that signs the bundle and the feed index.
    #[arg(long, short = 'k')]
    key: Option<PathBuf>,
    /// An age recipient (age1...) to encrypt the bundle and the feed index to; repeat for
    /// several. A feed that is encrypted needs them on every publish.
    #[arg(long, short = 'r', value_name = "RECIPIENT")]
    recipients: Vec<String>,
    /// An age identity file, to read the index of an encrypted feed that already exists.
    #[arg(long, short = 'i')]
    identity: Option<PathBuf>,
    /// Where to keep what is needed to delete bundles no stream points at, once the grace
    /// has passed. Without it nothing is deleted.
    #[arg(long)]
    state: Option<PathBuf>,
    /// Hours a bundle no stream points at is kept before --state deletes it; at least 1.
    #[arg(long, default_value = "24")]
    grace: f64,
    /// Remove the stream from the feed instead of publishing it.
    #[arg(long, conflicts_with = "inputs")]
    withdraw: bool,
    /// Record files (.json with $type and version) and attachments, or directories to
    /// publish every file in.
    #[arg(required_unless_present = "withdraw")]
    inputs: Vec<PathBuf>,
}

fn fail<T>(message: String) -> Result<T, Stop> {
    Err(Stop::Failed(message))
}

/// The feed as it already is in the directory.
struct Existing {
    feed: Feed,
    encrypted: bool,
}

pub fn run(command: FeedCommand) -> Result<(), Stop> {
    match command {
        FeedCommand::Publish(args) => publish(args),
        FeedCommand::Check(args) => check(args),
        FeedCommand::Pull(args) => pull_feed(args),
    }
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, Stop> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => fail(format!("{}: {e}", path.display())),
    }
}

/// Writes `bytes` to `path` so that nobody reading it sees half a file: to a
/// temporary file in the same directory, then a rename over `path`.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Stop> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Stop::Failed(format!("{}: not a file path", path.display())))?;
    let temp = path.with_file_name(format!(".{name}.tmp-{}", std::process::id()));
    let result = (|| {
        // A leftover from a run that died, under this same process id.
        let _ = std::fs::remove_file(&temp);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        std::io::Write::write_all(&mut file, bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)
    })();
    result.map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        Stop::Failed(format!("{}: {e}", path.display()))
    })
}

/// The index already in `dir`, if any. An index that can't be read is an
/// error, never a reason to start a new one over it.
fn read_existing(dir: &Path, identity: Option<&Path>) -> Result<Option<Existing>, Stop> {
    let plain = dir.join("feed.json");
    let sealed = dir.join("feed.json.age");
    let (path, bytes, encrypted) = match (read_optional(&plain)?, read_optional(&sealed)?) {
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => {
            return fail(format!(
                "{}: has both feed.json and feed.json.age; a feed is plain or encrypted, never both (remove one)",
                dir.display()
            ))
        }
        (Some(bytes), None) => (plain, bytes, false),
        (None, Some(bytes)) => (sealed, bytes, true),
    };
    let too_big = |bytes: &[u8]| bytes.len() as u64 > MAX_INDEX_BYTES;
    if too_big(&bytes) {
        return fail(format!(
            "{}: larger than a feed index may be",
            path.display()
        ));
    }
    let bytes = if encrypted {
        let Some(identity) = identity else {
            return fail(format!(
                "{}: the feed is encrypted, and its index has to be read to add to it; give the age identity file with -i",
                path.display()
            ));
        };
        let text = zeroize::Zeroizing::new(
            String::from_utf8(crate::read_input(identity)?)
                .map_err(|_| Stop::Failed(format!("{}: not text", identity.display())))?,
        );
        legible_records::age::decrypt(&bytes, &text, MAX_INDEX_BYTES)
            .map_err(|e| Stop::Failed(format!("{}: couldn't decrypt: {e}", path.display())))?
    } else {
        bytes
    };
    let unreadable = |e: String| {
        Stop::Failed(format!(
            "{}: {e}; not publishing over an index that can't be read (fix or remove it)",
            path.display()
        ))
    };
    let feed = parse_feed(&bytes).map_err(unreadable)?;
    check_bundle_paths(&feed, encrypted).map_err(unreadable)?;
    Ok(Some(Existing { feed, encrypted }))
}

/// The `$type`s of the inputs that are records.
fn types_in(inputs: &[Input]) -> Vec<String> {
    let mut found = BTreeSet::new();
    for input in inputs {
        if !input.name.to_ascii_lowercase().ends_with(".json") {
            continue;
        }
        if let Ok(Value::Object(record)) = serde_json::from_slice::<Value>(&input.bytes) {
            if let (Some(Value::String(t)), Some(Value::Number(v))) =
                (record.get("$type"), record.get("version"))
            {
                if v.is_u64() {
                    found.insert(t.clone());
                }
            }
        }
    }
    found.into_iter().collect()
}

/// The later of the two instants, as written.
fn later_of(a: String, b: &str) -> String {
    match (time::parse(&a), time::parse(b)) {
        (Ok(x), Ok(y)) if y > x => b.to_owned(),
        _ => a,
    }
}

fn publish(args: PublishArgs) -> Result<(), Stop> {
    // Arguments that can be checked on their own, before anything is read or written.
    if !is_feed_id(&args.feed) {
        return fail(format!(
            "--feed {:?}: a feed id is <publisher>/<slug>, such as acme.example/track",
            args.feed
        ));
    }
    let feed_publisher = args.feed.split_once('/').map_or("", |(p, _)| p).to_owned();
    if !is_slug(&args.stream) {
        return fail(format!(
            "--stream {:?}: use lowercase letters, digits and single hyphens",
            args.stream
        ));
    }
    if !args.grace.is_finite() || args.grace < 1.0 {
        return fail(format!(
            "--grace {}: the spec requires at least one hour, so a reader partway through a poll still finds its bundle",
            args.grace
        ));
    }
    let grace = Duration::try_from_secs_f64(args.grace * 3600.0)
        .map_err(|_| Stop::Failed(format!("--grace {}: too large", args.grace)))?;
    let key: Option<SigningKey> = match &args.key {
        Some(path) => Some(crate::read_key(path)?),
        None => None,
    };
    let publisher = match (&key, &args.publisher) {
        (Some(key), Some(given)) if *given != key.publisher => {
            return fail(format!(
                "--publisher {given}: the key is {}'s",
                key.publisher
            ))
        }
        (Some(key), _) => key.publisher.clone(),
        (None, Some(given)) if is_publisher(given) => given.clone(),
        (None, Some(given)) => {
            return fail(format!(
                "--publisher {given:?}: use a lowercase domain such as acme.example, with no scheme, port or path"
            ))
        }
        (None, None) => {
            return fail(
                "give --publisher <domain> (it comes from the key when you sign with -k)"
                    .to_owned(),
            )
        }
    };
    if publisher != feed_publisher {
        return fail(format!(
            "--feed {}: a feed's id starts with its publisher, {publisher}",
            args.feed
        ));
    }

    // What is there now.
    let existing = read_existing(&args.dir, args.identity.as_deref())?;
    let encrypted = match &existing {
        Some(existing) => existing.encrypted,
        None => !args.recipients.is_empty(),
    };
    if let Some(existing) = &existing {
        if existing.feed.id != args.feed {
            return fail(format!(
                "{}: holds the feed {}, not {}",
                args.dir.display(),
                existing.feed.id,
                args.feed
            ));
        }
        match (existing.encrypted, args.recipients.is_empty()) {
            (false, false) => {
                return fail(format!(
                    "{}: is a plain feed (feed.json); a feed is plain or encrypted, never both, so -r can't be used with it",
                    args.dir.display()
                ))
            }
            (true, true) => {
                return fail(format!(
                    "{}: is an encrypted feed (feed.json.age); give its recipients with -r",
                    args.dir.display()
                ))
            }
            _ => {}
        }
    }
    if key.is_none() && args.dir.join("feed.sig").exists() {
        return fail(format!(
            "{}: has a feed.sig, which an unsigned index would leave stale; publish with -k",
            args.dir.display()
        ));
    }

    let now = time::now();
    let previous_index = existing.as_ref().map(|e| e.feed.updated_at.as_str());
    let previous_stream = existing
        .as_ref()
        .and_then(|e| e.feed.streams.iter().find(|s| s.id == args.stream));
    let mut streams: Vec<StreamEntry> = existing
        .as_ref()
        .map(|e| e.feed.streams.clone())
        .unwrap_or_default();
    let mut updated_at = next_published_at(now, previous_index);

    // The new bundle, or the stream gone.
    let mut bundle_write: Option<(String, Vec<u8>)> = None;
    if args.withdraw {
        if previous_stream.is_none() {
            return fail(format!(
                "--withdraw: the feed has no stream {:?}",
                args.stream
            ));
        }
        streams.retain(|s| s.id != args.stream);
    } else {
        let published_at = next_published_at(now, previous_stream.map(|s| s.published_at.as_str()));
        updated_at = later_of(updated_at, &published_at);
        let mut inputs = Vec::new();
        let mut skipped = Vec::new();
        for path in &args.inputs {
            crate::collect(path, true, &mut inputs, &mut skipped)?;
        }
        if !skipped.is_empty() {
            eprintln!(
                "skipped {}: publishing packs a new manifest, so these are not packed",
                skipped.join(", ")
            );
        }
        if inputs.is_empty() {
            return fail("nothing to publish: the inputs hold no files".to_owned());
        }
        let record_types = if args.record_types.is_empty() {
            types_in(&inputs)
        } else {
            let mut seen = BTreeSet::new();
            args.record_types
                .iter()
                .filter(|t| seen.insert(t.as_str()))
                .cloned()
                .collect()
        };
        let options = PackOptions {
            produced_by: Some(serde_json::json!({
                "app": "legible",
                "version": env!("CARGO_PKG_VERSION"),
            })),
            published_at: Some(published_at.clone()),
            feed: Some((args.feed.clone(), args.stream.clone())),
            signer: key.as_ref(),
        };
        let packed = bundle::pack_with(&inputs, &[], &options).map_err(|problems| {
            problems.iter().for_each(|p| eprintln!("{p}"));
            Stop::Problems
        })?;
        let stored = if encrypted {
            legible_records::age::encrypt(&packed.zip, &args.recipients).map_err(Stop::Failed)?
        } else {
            packed.zip
        };
        let sha256 = bundle::sha256_hex(&stored);
        let path = format!(
            "bundles/{sha256}{}",
            if encrypted { ".zip.age" } else { ".zip" }
        );
        let entry = StreamEntry {
            id: args.stream.clone(),
            title: args.title.clone(),
            record_types,
            bundle: path.clone(),
            sha256,
            published_at,
        };
        match streams.iter_mut().find(|s| s.id == args.stream) {
            Some(slot) => *slot = entry,
            None => streams.push(entry),
        }
        bundle_write = Some((path, stored));
    }

    // The index, checked the way a reader checks it before it is written.
    let feed = Feed {
        id: args.feed.clone(),
        publisher,
        audience: args.audience.clone(),
        updated_at: updated_at.clone(),
        streams,
    };
    let index = render_feed(&feed);
    parse_feed(&index)
        .and_then(|parsed| check_bundle_paths(&parsed, encrypted).map(|()| parsed))
        .map_err(|e| Stop::Failed(format!("the new index wouldn't be accepted: {e}")))?;
    let stored_index = if encrypted {
        legible_records::age::encrypt(&index, &args.recipients).map_err(Stop::Failed)?
    } else {
        index
    };
    if stored_index.len() as u64 > MAX_INDEX_BYTES {
        return fail("the feed index would be larger than a reader reads".to_owned());
    }
    let signature = key
        .as_ref()
        .map(|key| sign::sign(key, Context::Feed, &stored_index).to_bytes());

    // Write: bundle, then index, then signature.
    std::fs::create_dir_all(args.dir.join("bundles"))
        .map_err(|e| Stop::Failed(format!("{}: {e}", args.dir.display())))?;
    if let Some((path, stored)) = &bundle_write {
        write_atomic(&args.dir.join(path), stored)?;
    }
    let index_name = if encrypted {
        "feed.json.age"
    } else {
        "feed.json"
    };
    write_atomic(&args.dir.join(index_name), &stored_index)?;
    if let Some(signature) = &signature {
        write_atomic(&args.dir.join("feed.sig"), signature)?;
    }
    match &bundle_write {
        Some((path, _)) => println!(
            "published {}: {path} (updated_at {updated_at})",
            args.stream
        ),
        None => println!("withdrew {} (updated_at {updated_at})", args.stream),
    }

    if let Some(state) = &args.state {
        collect_garbage(
            &args.dir,
            state,
            existing.as_ref().map(|e| e.feed.streams.as_slice()),
            &feed,
            now,
            grace,
        )?;
    }
    Ok(())
}

/// Notes the bundles that lost their last stream in this publish, forgets
/// ones a stream points at again, and deletes those unreferenced for at
/// least `grace`. Only a path in the state file is ever deleted, and only if
/// it is a bundle's path and no stream lists it.
fn collect_garbage(
    dir: &Path,
    state_path: &Path,
    old_streams: Option<&[StreamEntry]>,
    feed: &Feed,
    now: Instant,
    grace: Duration,
) -> Result<(), Stop> {
    let mut state = match read_optional(state_path)? {
        Some(bytes) => PublishState::parse(&bytes)
            .map_err(|e| Stop::Failed(format!("{}: {e}", state_path.display())))?,
        None => PublishState::default(),
    };
    let referenced: BTreeSet<&str> = feed.streams.iter().map(|s| s.bundle.as_str()).collect();
    for old in old_streams.unwrap_or_default() {
        if !referenced.contains(old.bundle.as_str()) {
            state
                .unreferenced_since
                .entry(old.bundle.clone())
                .or_insert_with(|| time::format(now));
        }
    }
    state
        .unreferenced_since
        .retain(|path, _| !referenced.contains(path.as_str()));
    for path in collectable(&state, now, grace) {
        let hash = path
            .strip_prefix("bundles/")
            .and_then(|rest| rest.strip_suffix(".zip.age").or(rest.strip_suffix(".zip")));
        if !hash.is_some_and(is_sha256) {
            return fail(format!(
                "{}: {path:?} is not a bundle path; not deleting it",
                state_path.display()
            ));
        }
        match std::fs::remove_file(dir.join(&path)) {
            Ok(()) => println!("deleted {path}"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return fail(format!("{}: {e}", dir.join(&path).display())),
        }
        state.unreferenced_since.remove(&path);
    }
    write_atomic(state_path, &state.to_bytes())
}

// ---- feed check | pull ----

/// A connection file, read and parsed.
fn read_connection(path: &Path) -> Result<Connection, Stop> {
    let bytes = crate::read_input(path)?;
    parse_connection(&bytes).map_err(|e| Stop::Failed(format!("{}: {e}", path.display())))
}

fn key_source(origin: Option<&str>) -> Result<Box<dyn KeySource>, Stop> {
    Ok(match origin {
        None => Box::new(HttpsKeySource::new()),
        Some(origin) => Box::new(
            HttpsKeySource::with_base(origin)
                .map_err(|e| Stop::Failed(format!("--key-origin: {e}")))?,
        ),
    })
}

/// The age identity the connection names, if the variable is set.
fn identity(conn: &Connection) -> Option<zeroize::Zeroizing<String>> {
    let name = conn.age_identity_env.as_deref()?;
    std::env::var(name).ok().map(zeroize::Zeroizing::new)
}

/// One poll, reading secrets from the environment the connection names.
fn poll(
    conn: &Connection,
    key_origin: Option<&str>,
    state: Option<&mut ReaderState>,
    etag: Option<String>,
    deliver: &mut dyn FnMut(legible_records::feed::Delivered) -> Result<(), String>,
) -> Result<PullReport, Stop> {
    let limits = Limits::default();
    let mut source = source_with_limits(conn, &|name| std::env::var(name).ok(), &limits)
        .map_err(Stop::Failed)?;
    let mut keys = key_source(key_origin)?;
    let identity = identity(conn);
    let options = PullOptions {
        identity: identity.as_ref().map(|i| i.as_str()),
        etag,
        limits,
    };
    Ok(pull(
        source.as_mut(),
        keys.as_mut(),
        conn,
        state,
        deliver,
        &options,
    ))
}

/// Prints what a poll found, and says whether it found anything to act on
/// (exit 1). A feed that couldn't be read at all is exit 2.
fn report_poll(
    report: &PullReport,
    signatures: &std::collections::BTreeMap<String, SignatureStatus>,
) -> Result<(), Stop> {
    for error in &report.fetch_errors {
        eprintln!("{error}");
    }
    let mut problems = false;
    match &report.index {
        IndexOutcome::Failed(e) => return fail(format!("index: failed: {e}")),
        IndexOutcome::Refused(code) => {
            println!("index: {}", code.as_str());
            problems = true;
        }
        IndexOutcome::NotModified => println!("index: not modified"),
        IndexOutcome::Accepted => {}
    }
    for (id, outcome) in &report.streams {
        match outcome {
            StreamOutcome::Accepted => match signatures.get(id) {
                Some(SignatureStatus::Verified { publisher, key }) => {
                    println!("{id}: accepted (verified {publisher} {key})")
                }
                _ => println!("{id}: accepted (unverified)"),
            },
            StreamOutcome::Unchanged => println!("{id}: unchanged"),
            StreamOutcome::Withdrawn => println!("{id}: withdrawn"),
            StreamOutcome::Refused(code) => {
                println!("{id}: {}", code.as_str());
                problems = true;
            }
            StreamOutcome::Failed(e) => {
                println!("{id}: failed: {e}");
                problems = true;
            }
        }
    }
    for pin in &report.pending_keys {
        println!(
            "pending key: --approve {}/{}={}",
            pin.publisher,
            pin.id,
            legible_records::sign::b64url(&pin.public_key)
        );
        problems = true;
    }
    if problems {
        Err(Stop::Problems)
    } else {
        Ok(())
    }
}

fn check(args: ReadArgs) -> Result<(), Stop> {
    let conn = read_connection(&args.connection)?;
    let mut signatures = std::collections::BTreeMap::new();
    let report = poll(&conn, args.key_origin.as_deref(), None, None, &mut |d| {
        signatures.insert(d.stream.id.clone(), d.signature);
        Ok(())
    })?;
    report_poll(&report, &signatures)
}

/// The state file's bytes: the reader state, and beside it the index's ETag
/// from the last poll that settled, so the next poll can ask `If-None-Match`.
fn render_state(state: &ReaderState, etag: Option<&str>) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(&state.to_bytes()).expect("state is JSON");
    if let (Some(etag), Some(object)) = (etag, value.as_object_mut()) {
        object.insert("etag".to_owned(), Value::from(etag));
    }
    bundle::canonical_record(&value)
}

/// What a state file held.
struct Held {
    state: ReaderState,
    etag: Option<String>,
    /// The file's bytes, if there was a file.
    bytes: Option<Vec<u8>>,
}

/// The state and ETag in a state file, or empty ones if there is no file.
fn load_state(path: &Path) -> Result<Held, Stop> {
    let Some(bytes) = read_optional(path)? else {
        return Ok(Held {
            state: ReaderState::default(),
            etag: None,
            bytes: None,
        });
    };
    let state =
        ReaderState::parse(&bytes).map_err(|e| Stop::Failed(format!("{}: {e}", path.display())))?;
    let etag = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| v.get("etag").and_then(Value::as_str).map(str::to_owned));
    Ok(Held {
        state,
        etag,
        bytes: Some(bytes),
    })
}

/// Writes `bytes` to `path` without ever replacing a file: to a temporary
/// file, then a hard link, which fails if `path` exists. A file already
/// there with the same bytes is the same delivery made again (a pull that
/// died before it saved its state), and is fine; any other is refused.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let fail = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
    let parent = path.parent().ok_or_else(|| fail(&"no directory"))?;
    std::fs::create_dir_all(parent).map_err(|e| fail(&e))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("bundle");
    let temp = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&temp);
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        std::io::Write::write_all(&mut file, bytes)?;
        file.sync_all()?;
        drop(file);
        match std::fs::hard_link(&temp, path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if std::fs::read(path)? == bytes {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        e.kind(),
                        "already exists with other contents; not overwriting it",
                    ))
                }
            }
            // A file system without hard links: rename, after checking it isn't there.
            Err(_) if !path.exists() => std::fs::rename(&temp, path),
            Err(e) => Err(e),
        }
    })();
    let _ = std::fs::remove_file(&temp);
    result.map_err(|e| fail(&e))
}

fn pull_feed(args: PullArgs) -> Result<(), Stop> {
    let approved = args
        .approve
        .iter()
        .map(|text| {
            crate::parse_pin(text).map_err(|e| Stop::Failed(format!("--approve {text}: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let conn = read_connection(&args.connection)?;
    let state_path = args
        .state
        .join(format!("{}.json", conn.feed.replace('/', "__")));
    let Held {
        mut state,
        etag,
        bytes: held_bytes,
    } = load_state(&state_path)?;
    let mut approving = false;
    for pin in approved {
        if !state.approved.contains(&pin) {
            state.approved.push(pin);
            approving = true;
        }
    }
    // A newly approved key can change what a poll accepts, so the index is
    // fetched whole.
    let etag = if approving { None } else { etag };

    let mut signatures = std::collections::BTreeMap::new();
    let out = args.out.clone();
    let report = poll(
        &conn,
        args.key_origin.as_deref(),
        Some(&mut state),
        etag.clone(),
        &mut |d| {
            let zip = bundle::to_zip(&d.bundle).map_err(|p| p.join("; "))?;
            let name = format!("{}.zip", d.published_at.replace(':', "-"));
            write_new(&out.join(&d.stream.id).join(name), &zip)?;
            signatures.insert(d.stream.id.clone(), d.signature);
            Ok(())
        },
    )?;

    // A refused or failed index changed nothing; the state stays as it was.
    let kept_etag = match &report.index {
        IndexOutcome::Accepted => report
            .etag
            .clone()
            .filter(|_| report.pending_keys.is_empty()),
        IndexOutcome::NotModified => etag,
        IndexOutcome::Refused(_) | IndexOutcome::Failed(_) => None,
    };
    if matches!(
        report.index,
        IndexOutcome::Accepted | IndexOutcome::NotModified
    ) {
        let bytes = render_state(&state, kept_etag.as_deref());
        if held_bytes.as_deref() != Some(bytes.as_slice()) {
            std::fs::create_dir_all(&args.state)
                .map_err(|e| Stop::Failed(format!("{}: {e}", args.state.display())))?;
            write_atomic(&state_path, &bytes)?;
        }
    }
    report_poll(&report, &signatures)
}
