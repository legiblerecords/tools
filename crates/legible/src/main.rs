//! `legible`: the Legible Records command-line tool.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use legible_records::bundle::{self, Input, Limits};
use legible_records::short_form::{self, Options};
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
    /// Pack, unpack and verify bundles. To encrypt one, pipe it through age.
    #[command(subcommand)]
    Bundle(BundleCommand),
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
        #[command(flatten)]
        schema: SchemaArgs,
    },
    /// Verify a bundle and write its files into a new or empty directory.
    Unpack {
        /// The bundle (.zip), or - for stdin.
        bundle: PathBuf,
        /// The directory to write into.
        #[arg(long, short = 'd')]
        directory: PathBuf,
        /// Schemas for checking record references; see verify.
        #[arg(long = "schema", short = 's')]
        schemas: Vec<PathBuf>,
        #[command(flatten)]
        schema: SchemaArgs,
    },
    /// Check a bundle's hashes, file list and references.
    Verify {
        /// The bundle (.zip), or - for stdin.
        bundle: PathBuf,
        /// A schema (.yaml or .json) whose records' references to check; repeat for several.
        /// Attachment references are always checked.
        #[arg(long = "schema", short = 's')]
        schemas: Vec<PathBuf>,
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
    }
}

fn run_bundle(command: BundleCommand) -> Result<(), Stop> {
    match command {
        BundleCommand::Pack {
            inputs,
            output,
            schemas,
            schema,
        } => {
            let bodies = load_schemas(&schemas, &schema)?;
            let mut files = Vec::new();
            for path in &inputs {
                collect(path, &mut files)?;
            }
            let produced_by = serde_json::json!({
                "app": "legible",
                "version": env!("CARGO_PKG_VERSION"),
            });
            let packed = bundle::pack(&files, &bodies, Some(produced_by)).map_err(|problems| {
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
            schemas,
            schema,
        } => {
            let opened = open_bundle(&path)?;
            verify_bundle(&path, &opened, &schemas, &schema)
        }
        BundleCommand::Unpack {
            bundle: path,
            directory,
            schemas,
            schema,
        } => {
            let opened = open_bundle(&path)?;
            verify_bundle(&path, &opened, &schemas, &schema)?;
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
            let manifest =
                serde_json::to_vec_pretty(&opened.manifest).expect("JSON values serialize");
            let files = std::iter::once((bundle::MANIFEST, &manifest))
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
/// Symbolic links are skipped.
fn collect(path: &Path, out: &mut Vec<Input>) -> Result<(), Stop> {
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
            collect(&entry, out)?;
        }
    } else if kind.is_file() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Stop::Failed(format!("{}: not a UTF-8 file name", path.display())))?;
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

fn open_bundle(path: &Path) -> Result<bundle::Opened, Stop> {
    let bytes = read_input(path)?;
    if bytes.starts_with(b"age-encryption.org/") || bytes.starts_with(b"-----BEGIN AGE") {
        return Err(Stop::Failed(format!(
            "{}: encrypted with age; decrypt it first (age -d)",
            path.display()
        )));
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
    args: &SchemaArgs,
) -> Result<(), Stop> {
    let bodies = load_schemas(schemas, args)?;
    let report = bundle::verify(opened, &bodies);
    for problem in &report.problems {
        println!("{}: {problem}", path.display());
    }
    for kind in &report.unchecked_types {
        eprintln!(
            "{}: no schema given for {kind}; its references weren't checked",
            path.display()
        );
    }
    outcome(report.problems.is_empty())
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
