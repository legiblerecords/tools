//! `legible`: the Legible Records command-line tool.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
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
}

#[derive(Args, Clone)]
struct SchemaArgs {
    /// The schema's name, for its own `<name>.<def>` references. Defaults to
    /// the file name without `.schema`, `.yaml` or `.json`.
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
