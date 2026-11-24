//! `legible`: the Legible Records command-line tool.

mod feed_cmd;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use legible_records::bundle::{self, Input, Limits, SignatureStatus};
use legible_records::code::Code;
use legible_records::keys::{parse_pin_text, KeySet, Trust};
use legible_records::short_form::{self, Options};
use legible_records::sign::{self, Context, SignatureFile, SigningKey};
use legible_records::validate::Schemas;
use legible_records::{compat, lint, COMMON_V1_ID};
use serde_json::Value;

#[derive(Parser)]
#[command(
    name = "legible",
    version,
    about = "Legible Records: legible, portable, pragmatic security records",
    long_about = "Expand and generate short-form schemas, lint published types, check \
                  compatibility between versions, and validate records.\n\n\
                  Exit status: 0 when everything passes, 1 when the input has problems, \
                  2 when the tool couldn't run."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Expand a short-form schema (.yaml) to JSON Schema, printed to stdout.
    Expand {
        file: PathBuf,
        #[command(flatten)]
        schema: SchemaArgs,
    },
    /// Generate the canonical short form of a JSON Schema (.json), printed to stdout.
    Generate {
        file: PathBuf,
        #[command(flatten)]
        schema: SchemaArgs,
    },
    /// Check that a published type stays within the published subset.
    Lint {
        /// A short-form (.yaml) or expanded (.json) schema.
        file: PathBuf,
        #[command(flatten)]
        schema: SchemaArgs,
    },
    /// Check that a new version of a type is compatible with the old one.
    CheckCompat {
        old: PathBuf,
        new: PathBuf,
        #[command(flatten)]
        schema: SchemaArgs,
    },
    /// Validate records against their types, chosen by each record's $type and version.
    Validate {
        /// A schema to use (.yaml or .json); repeat for several. org.legiblerecords.common
        /// version 1 is always included. Nothing is fetched from the network.
        #[arg(long = "schema", short = 's', required = true)]
        schemas: Vec<PathBuf>,
        /// Record files (.json).
        #[arg(required = true)]
        records: Vec<PathBuf>,
        #[command(flatten)]
        schema: SchemaArgs,
    },
    /// Pack, sign, verify and unpack bundles. To encrypt one, pipe it through age; verify and
    /// unpack decrypt with -i.
    #[command(subcommand)]
    Bundle(BundleCommand),
    /// Make signing keys, and endorse key sets with them.
    #[command(subcommand)]
    Keys(KeysCommand),
    /// Feeds: publish a stream into a feed's directory, check a feed (stateless), or pull one,
    /// keeping what the reader remembers.
    #[command(subcommand)]
    Feed(feed_cmd::FeedCommand),
}

#[derive(Subcommand)]
enum KeysCommand {
    /// Make a signing key. The secret key goes to a new file (mode 0600); the entry to add
    /// to your keys.json is printed to stdout.
    New {
        /// Your domain, such as acme.example.
        #[arg(long)]
        publisher: String,
        /// A name for the key, such as 2026-11.
        #[arg(long)]
        id: String,
        /// Where to write the secret key. An existing file is refused.
        #[arg(long, short = 'o')]
        output: PathBuf,
    },
    /// Sign a key set (keys.json) with a key, writing keys.sig. The key must already be
    /// in the key set readers hold: that is what makes the new set an endorsed one.
    Sign {
        /// The key set (.json), signed exactly as stored.
        keys: PathBuf,
        /// The secret key file from `keys new`.
        #[arg(long, short = 'k')]
        key: PathBuf,
        /// Where to write keys.sig, or - for stdout.
        #[arg(long, short = 'o')]
        output: PathBuf,
    },
}

#[derive(Args, Clone)]
struct TrustArgs {
    /// A key to trust, as <publisher>/<id>=<public_key> (base64url); repeat for several.
    #[arg(long = "pin", value_name = "PUBLISHER/ID=PUBLIC_KEY")]
    pins: Vec<String>,
    /// A publisher's key set (keys.json) to trust; repeat for several. A file only:
    /// nothing is fetched.
    #[arg(long = "key-set", value_name = "FILE")]
    key_sets: Vec<PathBuf>,
}

impl TrustArgs {
    /// The keys given, or a message for a pin or key set that can't be used.
    fn trust(&self) -> Result<Trust, Stop> {
        let mut trust = Trust::default();
        for text in &self.pins {
            let pin =
                parse_pin_text(text).map_err(|e| Stop::Failed(format!("--pin {text}: {e}")))?;
            trust.pins.push(pin);
        }
        for path in &self.key_sets {
            let bytes = read_input(path)?;
            let set = KeySet::parse(&bytes)
                .map_err(|code| Stop::Failed(format!("{}: {}", path.display(), code.as_str())))?;
            let publisher = set.publisher.clone();
            if trust.key_sets.insert(publisher.clone(), set).is_some() {
                return Err(Stop::Failed(format!(
                    "{}: a second key set for {publisher}",
                    path.display()
                )));
            }
        }
        Ok(trust)
    }

    fn given(&self) -> bool {
        !self.pins.is_empty() || !self.key_sets.is_empty()
    }
}

#[derive(Subcommand)]
enum BundleCommand {
    /// Pack records (.json with $type and version) and attachments (anything else) into a bundle.
    Pack {
        /// Files, or directories to pack every file in.
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        /// Where to write the bundle (.zip), or - for stdout.
        #[arg(long, short = 'o')]
        output: PathBuf,
        /// Schemas (.yaml or .json) of the records' types: a record's folder is its type's
        /// title, or the type's last segment when no schema is given.
        #[arg(long = "schema", short = 's')]
        schemas: Vec<PathBuf>,
        /// Write this kind's records as one record set, records/<kind>.ndjson; repeat for
        /// several. Without it, a kind with more than 1,000 records (across its versions) is
        /// written as a set. .ndjson inputs are always packed as the sets they are.
        #[arg(long = "set", value_name = "KIND", conflicts_with = "no_sets")]
        sets: Vec<String>,
        /// Write every record as its own file (except .ndjson inputs).
        #[arg(long = "no-sets")]
        no_sets: bool,
        #[command(flatten)]
        schema: SchemaArgs,
    },
    /// Verify a bundle and write its files into a new or empty directory.
    Unpack {
        /// The bundle (.zip or encrypted .zip.age), or - for stdin.
        bundle: PathBuf,
        /// The directory to write into.
        #[arg(long, short = 'd')]
        directory: PathBuf,
        /// An age identity file, to decrypt a bundle that is encrypted.
        #[arg(long, short = 'i')]
        identity: Option<PathBuf>,
        /// Schemas for checking record references; see verify.
        #[arg(long = "schema", short = 's')]
        schemas: Vec<PathBuf>,
        #[command(flatten)]
        trust: TrustArgs,
        #[command(flatten)]
        schema: SchemaArgs,
    },
    /// Sign a bundle's manifest as stored, writing a copy with manifest.sig.
    Sign {
        /// The bundle (.zip), or - for stdin. One that is already signed is refused.
        bundle: PathBuf,
        /// The secret key file from `keys new`.
        #[arg(long, short = 'k')]
        key: PathBuf,
        /// Where to write the signed bundle (.zip), or - for stdout.
        #[arg(long, short = 'o')]
        output: PathBuf,
    },
    /// Check a bundle's hashes, file list, references and signature.
    ///
    /// Exit 0 doesn't mean a signature was checked: it did only when the signature line
    /// says `verified`, which needs --pin or --key-set. Without them, a signed bundle is
    /// reported `unverified`, and a bad bundle is still exit 1.
    Verify {
        /// The bundle (.zip or encrypted .zip.age), or - for stdin.
        bundle: PathBuf,
        /// An age identity file, to decrypt a bundle that is encrypted.
        #[arg(long, short = 'i')]
        identity: Option<PathBuf>,
        /// A schema (.yaml or .json) whose records' references to check; repeat for several.
        /// Attachment references are always checked.
        #[arg(long = "schema", short = 's')]
        schemas: Vec<PathBuf>,
        #[command(flatten)]
        trust: TrustArgs,
        #[command(flatten)]
        schema: SchemaArgs,
    },
}

#[derive(Args, Clone)]
struct SchemaArgs {
    /// The schema's name, for its own `<name>.<def>` references. Defaults to
    /// the file name without `.schema`, `.yaml` or `.json`. A published type
    /// can always use its title instead.
    #[arg(long, global = true)]
    name: Option<String>,
    /// The base URL of a published type's $id, such as https://monorail.tech/schemas/.
    /// Given a base, bare names such as `date` point at org.legiblerecords.common
    /// unless --common says otherwise.
    #[arg(long, global = true)]
    base: Option<String>,
    /// Where bare names such as `date` point.
    #[arg(long, global = true)]
    common: Option<String>,
    /// Where `<schema>.<def>` points, with `{name}` for the schema.
    #[arg(long, global = true)]
    location: Option<String>,
}

impl SchemaArgs {
    fn options(&self) -> Options {
        let mut options = match &self.base {
            Some(base) => Options::published(base),
            None => Options::default(),
        };
        if let Some(common) = &self.common {
            options.common = common.clone();
        }
        if let Some(location) = &self.location {
            options.location = location.clone();
        }
        options
    }

    fn name_for(&self, path: &Path) -> String {
        if let Some(name) = &self.name {
            return name.clone();
        }
        let file = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("schema");
        let mut name = file;
        for suffix in [".yaml", ".yml", ".json"] {
            name = name.strip_suffix(suffix).unwrap_or(name);
        }
        name.strip_suffix(".schema").unwrap_or(name).to_owned()
    }
}

/// Why the tool stopped: problems in the input (exit 1) or a failure to run (exit 2).
enum Stop {
    Problems,
    Failed(String),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Stop::Problems) => ExitCode::from(1),
        Err(Stop::Failed(message)) => {
            eprintln!("legible: {message}");
            ExitCode::from(2)
        }
    }
}

fn run(command: Command) -> Result<(), Stop> {
    match command {
        Command::Feed(command) => feed_cmd::run(command),
        Command::Expand { file, schema } => {
            let body = load_schema(&file, &schema)?;
            println!("{}", pretty(&body));
            Ok(())
        }
        Command::Generate { file, schema } => {
            let body = read_json(&file)?;
            let short = short_form::generate(&body, &schema.name_for(&file), &schema.options())
                .map_err(|e| Stop::Failed(format!("{}: {e}", file.display())))?;
            print!("{short}");
            Ok(())
        }
        Command::Lint { file, schema } => {
            let body = load_schema(&file, &schema)?;
            let findings = lint::lint(&body);
            for finding in &findings {
                println!(
                    "{}: {}: {}",
                    file.display(),
                    pointer(&finding.pointer),
                    finding.message
                );
            }
            outcome(findings.is_empty())
        }
        Command::CheckCompat { old, new, schema } => {
            let old_body = load_schema(&old, &schema)?;
            let new_body = load_schema(&new, &schema)?;
            let breaks = compat::check(&old_body, &new_body);
            for change in &breaks {
                println!(
                    "{}: {}: {}",
                    old.display(),
                    pointer(&change.pointer),
                    change.message
                );
            }
            outcome(breaks.is_empty())
        }
        Command::Validate {
            schemas,
            records,
            schema,
        } => {
            let mut set = Schemas::default();
            for path in &schemas {
                let body = load_schema(path, &schema)?;
                set.add(body)
                    .map_err(|e| Stop::Failed(format!("{}: {e}", path.display())))?;
            }
            let mut ok = true;
            for path in &records {
                let record = read_json(path)?;
                let Some(type_schema) = set.for_record(&record) else {
                    ok = false;
                    let kind = record
                        .get("$type")
                        .map_or("no $type".to_owned(), Value::to_string);
                    let version = record
                        .get("version")
                        .map_or("no version".to_owned(), Value::to_string);
                    println!(
                        "{}: no schema given for {kind} version {version} (common is {COMMON_V1_ID})",
                        path.display()
                    );
                    continue;
                };
                let failures = set
                    .validate(type_schema, &record)
                    .map_err(|e| Stop::Failed(e.to_string()))?;
                for failure in &failures {
                    println!(
                        "{}: {}: {}",
                        path.display(),
                        pointer(&failure.pointer),
                        failure.message
                    );
                }
                ok &= failures.is_empty();
            }
            outcome(ok)
        }
        Command::Bundle(command) => run_bundle(command),
        Command::Keys(command) => run_keys(command),
    }
}

fn run_bundle(command: BundleCommand) -> Result<(), Stop> {
    match command {
        BundleCommand::Pack {
            inputs,
            output,
            schemas,
            sets,
            no_sets,
            schema,
        } => {
            let bodies = load_schemas(&schemas, &schema)?;
            let mut files = Vec::new();
            let mut skipped = Vec::new();
            for path in &inputs {
                collect(path, true, &mut files, &mut skipped)?;
            }
            if !skipped.is_empty() {
                eprintln!(
                    "skipped {}: packing writes a new manifest, so the result is a new, unsigned bundle, not the one these came from",
                    skipped.join(", ")
                );
            }
            let produced_by = serde_json::json!({
                "app": "legible",
                "version": env!("CARGO_PKG_VERSION"),
            });
            let options = bundle::PackOptions {
                produced_by: Some(produced_by),
                sets: if no_sets {
                    bundle::SetMode::Never
                } else if sets.is_empty() {
                    bundle::SetMode::Auto
                } else {
                    bundle::SetMode::Kinds(sets)
                },
                ..bundle::PackOptions::default()
            };
            let packed = bundle::pack_with(&files, &bodies, &options).map_err(|problems| {
                problems.iter().for_each(|p| eprintln!("{p}"));
                Stop::Problems
            })?;
            write_output(&output, &packed.zip)?;
            for a in &packed.attachments {
                let reference = serde_json::json!({"sha256": a.sha256, "name": a.name, "media_type": a.media_type});
                eprintln!("attachment {}: {reference}", a.name);
            }
            Ok(())
        }
        BundleCommand::Verify {
            bundle: path,
            identity,
            schemas,
            trust,
            schema,
        } => {
            let opened = open_bundle(&path, identity.as_deref())?;
            verify_bundle(&path, &opened, &schemas, &trust, &schema)
        }
        BundleCommand::Sign {
            bundle: path,
            key,
            output,
        } => {
            let key = read_key(&key)?;
            let zip = read_input(&path)?;
            let signed =
                bundle::add_signature(&zip, &key, Limits::default()).map_err(|problems| {
                    problems
                        .iter()
                        .for_each(|p| println!("{}: {p}", path.display()));
                    Stop::Problems
                })?;
            write_output(&output, &signed)
        }
        BundleCommand::Unpack {
            bundle: path,
            directory,
            identity,
            schemas,
            trust,
            schema,
        } => {
            let opened = open_bundle(&path, identity.as_deref())?;
            verify_bundle(&path, &opened, &schemas, &trust, &schema)?;
            let empty = match std::fs::read_dir(&directory) {
                Ok(mut entries) => entries.next().is_none(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                Err(e) => return Err(Stop::Failed(format!("{}: {e}", directory.display()))),
            };
            if !empty {
                return Err(Stop::Failed(format!(
                    "{}: not empty; unpack into a new or empty directory",
                    directory.display()
                )));
            }
            // The manifest and signature as stored: a signature covers these exact bytes.
            let files = std::iter::once((bundle::MANIFEST, &opened.manifest_bytes))
                .chain(
                    opened
                        .signature
                        .as_ref()
                        .map(|bytes| (bundle::SIGNATURE, bytes)),
                )
                .chain(opened.files.iter().map(|(p, b)| (p.as_str(), b)));
            for (relative, bytes) in files {
                let target = directory.join(relative);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| Stop::Failed(format!("{}: {e}", parent.display())))?;
                }
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)
                    .map_err(|e| Stop::Failed(format!("{}: {e}", target.display())))?;
                std::io::Write::write_all(&mut file, bytes)
                    .map_err(|e| Stop::Failed(format!("{}: {e}", target.display())))?;
            }
            Ok(())
        }
    }
}

/// Reads a file, or every regular file under a directory, as bundle inputs.
/// Symbolic links are skipped. A `manifest.json` or `manifest.sig` among the
/// inputs themselves or directly in a directory given as one (an unpacked
/// bundle's own) isn't packed: its path is added to `skipped`.
fn collect(
    path: &Path,
    top: bool,
    out: &mut Vec<Input>,
    skipped: &mut Vec<String>,
) -> Result<(), Stop> {
    let failed = |e: std::io::Error| Stop::Failed(format!("{}: {e}", path.display()));
    let kind = std::fs::symlink_metadata(path).map_err(failed)?.file_type();
    if kind.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
            .map_err(failed)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<_, _>>()
            .map_err(failed)?;
        entries.sort();
        for entry in entries {
            // Only the directory's own files can be a bundle's manifest or signature.
            collect(&entry, top && !entry.is_dir(), out, skipped)?;
        }
    } else if kind.is_file() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Stop::Failed(format!("{}: not a UTF-8 file name", path.display())))?;
        if top && (name == bundle::MANIFEST || name == bundle::SIGNATURE) {
            skipped.push(path.display().to_string());
            return Ok(());
        }
        out.push(Input {
            name: name.to_owned(),
            bytes: std::fs::read(path).map_err(failed)?,
        });
    }
    Ok(())
}

fn read_input(path: &Path) -> Result<Vec<u8>, Stop> {
    if path == Path::new("-") {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes)
            .map_err(|e| Stop::Failed(format!("stdin: {e}")))?;
        return Ok(bytes);
    }
    std::fs::read(path).map_err(|e| Stop::Failed(format!("{}: {e}", path.display())))
}

fn write_output(path: &Path, bytes: &[u8]) -> Result<(), Stop> {
    if path == Path::new("-") {
        return std::io::Write::write_all(&mut std::io::stdout(), bytes)
            .map_err(|e| Stop::Failed(format!("stdout: {e}")));
    }
    std::fs::write(path, bytes).map_err(|e| Stop::Failed(format!("{}: {e}", path.display())))
}

fn open_bundle(path: &Path, identity: Option<&Path>) -> Result<bundle::Opened, Stop> {
    let stdin = Path::new("-");
    if path == stdin && identity == Some(stdin) {
        return Err(Stop::Failed(
            "-i -: the bundle is already read from stdin; give the identity as a file".to_owned(),
        ));
    }
    let mut bytes = read_input(path)?;
    if legible_records::age::is_encrypted(&bytes) {
        let Some(identity) = identity else {
            return Err(Stop::Failed(format!(
                "{}: encrypted with age; give the identity file with -i",
                path.display()
            )));
        };
        let text = zeroize::Zeroizing::new(
            String::from_utf8(read_input(identity)?)
                .map_err(|_| Stop::Failed(format!("{}: not text", identity.display())))?,
        );
        bytes = legible_records::age::decrypt(&bytes, &text, Limits::default().max_stored_bytes())
            .map_err(|e| {
                println!("{}: couldn't decrypt: {e}", path.display());
                Stop::Problems
            })?;
    }
    bundle::open(&bytes, Limits::default()).map_err(|problems| {
        for problem in &problems {
            println!("{}: {problem}", path.display());
        }
        Stop::Problems
    })
}

fn load_schemas(paths: &[PathBuf], args: &SchemaArgs) -> Result<Vec<Value>, Stop> {
    paths.iter().map(|path| load_schema(path, args)).collect()
}

fn verify_bundle(
    path: &Path,
    opened: &bundle::Opened,
    schemas: &[PathBuf],
    trust_args: &TrustArgs,
    args: &SchemaArgs,
) -> Result<(), Stop> {
    let bodies = load_schemas(schemas, args)?;
    let trust = trust_args.trust()?;
    let report = bundle::verify_at(opened, &bodies, legible_records::time::now());
    for problem in &report.problems {
        println!("{}: {problem}", path.display());
    }
    for kind in &report.unchecked_types {
        eprintln!(
            "{}: no schema given for {kind}; its references weren't checked",
            path.display()
        );
    }
    let status = signature_status(opened, &trust, trust_args.given());
    println!("{}", signature_line(opened, &status));
    outcome(report.problems.is_empty() && status.is_ok())
}

/// A bundle's signature against what the reader trusts. A signed bundle with
/// no trusted keys given isn't checked: it is `Unverified`, which is not a
/// failure. Any `Code` is a problem with the bundle.
fn signature_status(
    opened: &bundle::Opened,
    trust: &Trust,
    trust_given: bool,
) -> Result<SignatureStatus, Code> {
    if !trust_given {
        if let Some(bytes) = &opened.signature {
            SignatureFile::parse(bytes)?;
            return Ok(SignatureStatus::Unverified);
        }
    }
    bundle::check_signature(opened, trust, None)
}

/// The line `bundle verify` prints about the signature, for every outcome.
fn signature_line(opened: &bundle::Opened, status: &Result<SignatureStatus, Code>) -> String {
    match status {
        Ok(SignatureStatus::Verified { publisher, key, .. }) => {
            format!("signature: verified ({publisher} {key})")
        }
        Ok(SignatureStatus::Unverified) => {
            match opened
                .signature
                .as_deref()
                .and_then(|bytes| SignatureFile::parse(bytes).ok())
            {
                Some(sig) => format!(
                    "signature: unverified (signed by {} {}; no trusted keys given)",
                    sig.publisher, sig.key
                ),
                None => "signature: unverified".to_owned(),
            }
        }
        Err(code) => format!("signature: {}", code.as_str()),
    }
}

fn read_key(path: &Path) -> Result<SigningKey, Stop> {
    let bytes = zeroize::Zeroizing::new(read_input(path)?);
    SigningKey::from_json(&bytes).map_err(|e| Stop::Failed(format!("{}: {e}", path.display())))
}

fn run_keys(command: KeysCommand) -> Result<(), Stop> {
    match command {
        KeysCommand::New {
            publisher,
            id,
            output,
        } => {
            if output == Path::new("-") {
                return Err(Stop::Failed(
                    "-o -: the secret key goes to a file, not stdout".to_owned(),
                ));
            }
            let key = SigningKey::generate(&publisher, &id).map_err(Stop::Failed)?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            // Created private: never written and then restricted.
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut file = options
                .open(&output)
                .map_err(|e| Stop::Failed(format!("{}: {e}", output.display())))?;
            if let Err(e) = std::io::Write::write_all(&mut file, &key.to_json()) {
                drop(file);
                let _ = std::fs::remove_file(&output);
                return Err(Stop::Failed(format!("{}: {e}", output.display())));
            }
            let entry = serde_json::json!({
                "id": key.id,
                "alg": "ed25519",
                "public_key": sign::b64url(&key.public().key),
                "created_at": legible_records::time::format(legible_records::time::now()),
            });
            println!("{}", pretty(&entry));
            Ok(())
        }
        KeysCommand::Sign { keys, key, output } => {
            let key = read_key(&key)?;
            let bytes = read_input(&keys)?;
            let set = KeySet::parse(&bytes)
                .map_err(|code| Stop::Failed(format!("{}: {}", keys.display(), code.as_str())))?;
            if set.publisher != key.publisher {
                return Err(Stop::Failed(format!(
                    "{}: the key set is for {}, but the key is {}'s",
                    keys.display(),
                    set.publisher,
                    key.publisher
                )));
            }
            let public = key.public().key;
            if !set
                .keys
                .iter()
                .any(|k| k.id == key.id && k.public_key == public)
            {
                eprintln!(
                    "warning: {}: {}/{} isn't in this key set; readers only take an endorsement from a key they already hold",
                    keys.display(),
                    key.publisher,
                    key.id
                );
            }
            let signature = sign::sign(&key, Context::Keys, &bytes);
            write_output(&output, &signature.to_bytes())
        }
    }
}

fn outcome(ok: bool) -> Result<(), Stop> {
    if ok {
        Ok(())
    } else {
        Err(Stop::Problems)
    }
}

fn pointer(pointer: &str) -> &str {
    if pointer.is_empty() {
        "/"
    } else {
        pointer
    }
}

fn read(path: &Path) -> Result<String, Stop> {
    std::fs::read_to_string(path).map_err(|e| Stop::Failed(format!("{}: {e}", path.display())))
}

fn read_json(path: &Path) -> Result<Value, Stop> {
    serde_json::from_str(&read(path)?)
        .map_err(|e| Stop::Failed(format!("{}: not JSON: {e}", path.display())))
}

/// A schema from a short-form (.yaml, .yml) or JSON file, expanded.
fn load_schema(path: &Path, args: &SchemaArgs) -> Result<Value, Stop> {
    let is_yaml = matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yaml" | "yml")
    );
    if !is_yaml {
        return read_json(path);
    }
    let text = read(path)?;
    short_form::expand(&text, &args.name_for(path), &args.options()).map_err(|problems| {
        for problem in &problems {
            if problem.path.is_empty() {
                eprintln!("{}:{}: {}", path.display(), problem.line, problem.message);
            } else {
                eprintln!(
                    "{}:{}: {}: {}",
                    path.display(),
                    problem.line,
                    problem.path,
                    problem.message
                );
            }
        }
        Stop::Problems
    })
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).expect("JSON values serialize")
}
