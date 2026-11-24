//! Bundles (spec/records.md § Bundles): records and attachments in one zip,
//! with a manifest of every file and its SHA-256.
//!
//! [`pack`] builds a bundle from files; [`open`] reads one back, refusing
//! unsafe paths and oversized contents; [`verify`] checks hashes, the file
//! list and references. A bundle may carry `manifest.sig`, a signature over
//! the manifest's stored bytes: [`pack_with`] and [`add_signature`] write it
//! and [`check_signature`] reads it. Encryption is a separate step around
//! the zip.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::code::Code;
use crate::keys::{KeyState, Lookup, Trust};
use crate::sign::{self, Context, SignatureFile, SigningKey};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

/// The manifest's own path in a bundle.
pub const MANIFEST: &str = "manifest.json";
/// The manifest signature's path in a bundle.
pub const SIGNATURE: &str = "manifest.sig";
/// The manifest's type.
pub const BUNDLE_TYPE: &str = "org.legiblerecords.bundle";

/// Limits on what [`open`] will read, so a crafted zip can't exhaust memory.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_files: usize,
    pub max_total_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_files: 10_000,
            max_total_bytes: 1 << 30,
        }
    }
}

/// A file to put in a bundle: its own name (for an attachment, the name
/// people see) and its bytes.
#[derive(Clone, Debug)]
pub struct Input {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// An attachment as records refer to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub sha256: String,
    pub name: String,
    pub media_type: String,
}

/// A packed bundle.
#[derive(Clone, Debug)]
pub struct Packed {
    pub zip: Vec<u8>,
    pub manifest: Value,
    pub attachments: Vec<Attachment>,
}

/// An opened bundle: its manifest (parsed, and as stored, which is what a
/// signature covers), its signature if it has one, and every other file by
/// path. `files` holds neither `manifest.json` nor `manifest.sig`.
#[derive(Clone, Debug)]
pub struct Opened {
    pub manifest: Value,
    pub manifest_bytes: Vec<u8>,
    pub signature: Option<Vec<u8>>,
    pub files: BTreeMap<String, Vec<u8>>,
}

/// What [`pack_with`] adds to a bundle beyond its files.
#[derive(Default)]
pub struct PackOptions<'a> {
    /// The manifest's `produced_by`.
    pub produced_by: Option<Value>,
    /// The manifest's `published_at`, an RFC 3339 instant.
    pub published_at: Option<String>,
    /// The feed id and stream id the bundle is published under.
    pub feed: Option<(String, String)>,
    /// Signs the manifest, writing `manifest.sig`.
    pub signer: Option<&'a SigningKey>,
}

/// What [`check_signature`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Signed by a trusted key that is active or retired.
    Verified { publisher: String, key: String },
    /// Not signed, and from no publisher the reader trusts.
    Unverified,
}

/// What [`verify`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Everything wrong with the bundle; empty when it verifies.
    pub problems: Vec<String>,
    /// Record types with no schema given, whose references couldn't be checked.
    pub unchecked_types: Vec<String>,
}

/// SHA-256 of `bytes`, as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A record's bytes as a writer must write them: sorted keys, two-space
/// indentation, one final newline.
pub fn canonical_record(record: &Value) -> Vec<u8> {
    let mut text = serde_json::to_string_pretty(record).expect("JSON values serialize");
    text.push('\n');
    text.into_bytes()
}

fn media_type(name: &str) -> &'static str {
    let ext = name
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "json" => "application/json",
        "csv" => "text/csv",
        "txt" | "log" => "text/plain",
        "md" => "text/markdown",
        "html" | "htm" => "text/html",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

fn is_key(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The type and version of a JSON file that is a record.
fn record_type(value: &Value) -> Option<(&str, u64)> {
    Some((
        value.get("$type")?.as_str()?,
        value.get("version")?.as_u64()?,
    ))
}

/// The schema among `schemas` for a type and version, matched by the consts
/// on its `$type` and `version` properties.
fn schema_for<'a>(schemas: &'a [Value], kind: &str, version: u64) -> Option<&'a Value> {
    schemas.iter().find(|schema| {
        let property = |name: &str| schema.get("properties")?.get(name)?.get("const");
        property("$type") == Some(&json!(kind)) && property("version") == Some(&json!(version))
    })
}

/// A type's short name, for paths and references: its schema's `title`
/// when the schema is among `schemas`, otherwise the type identifier's last
/// segment.
pub fn kind_of(schemas: &[Value], record_type: &str, version: u64) -> String {
    schema_for(schemas, record_type, version)
        .and_then(|schema| schema.get("title"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| record_type.rsplit('.').next().unwrap_or(record_type))
        .to_owned()
}

/// Builds a bundle. A `.json` input with `$type` and `version` is a record,
/// stored at `records/<kind>/<id>.json`, where `kind` is its type's short
/// name (see [`kind_of`]) and `id` its `id` (or file name). Anything else is an
/// attachment, stored at `files/<sha256>`. The zip is the same bytes for the
/// same inputs.
pub fn pack(
    inputs: &[Input],
    schemas: &[Value],
    produced_by: Option<Value>,
) -> Result<Packed, Vec<String>> {
    let options = PackOptions {
        produced_by,
        ..PackOptions::default()
    };
    pack_with(inputs, schemas, &options)
}

/// [`pack`] with the rest of what a manifest may say, and optionally a
/// signature over it.
pub fn pack_with(
    inputs: &[Input],
    schemas: &[Value],
    options: &PackOptions,
) -> Result<Packed, Vec<String>> {
    let mut problems = Vec::new();
    let mut files: BTreeMap<String, (Vec<u8>, Map<String, Value>)> = BTreeMap::new();
    let mut attachments = Vec::new();
    for input in inputs {
        let record = input
            .name
            .to_ascii_lowercase()
            .ends_with(".json")
            .then(|| serde_json::from_slice::<Value>(&input.bytes).ok())
            .flatten()
            .filter(|value| record_type(value).is_some());
        if let Some(record) = record {
            let (kind_id, version) = record_type(&record).expect("checked above");
            let kind = kind_of(schemas, kind_id, version);
            let stem = input
                .name
                .rsplit('/')
                .next()
                .unwrap_or(&input.name)
                .trim_end_matches(".json")
                .to_owned();
            let key = record
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or(stem);
            if !is_key(&kind) || !is_key(&key) {
                problems.push(format!(
                    "{}: a record's kind and id must be lowercase letters, digits and hyphens (got {kind}/{key})",
                    input.name
                ));
                continue;
            }
            let path = format!("records/{kind}/{key}.json");
            let bytes = canonical_record(&record);
            let mut entry = Map::new();
            entry.insert("record_type".to_owned(), json!(kind_id));
            entry.insert("record_version".to_owned(), json!(version));
            if files.insert(path.clone(), (bytes, entry)).is_some() {
                problems.push(format!("{}: two records would both be {path}", input.name));
            }
        } else {
            let sha = sha256_hex(&input.bytes);
            let name = input
                .name
                .rsplit('/')
                .next()
                .unwrap_or(&input.name)
                .to_owned();
            let media = media_type(&name).to_owned();
            let mut entry = Map::new();
            entry.insert("media_type".to_owned(), json!(media));
            files.insert(format!("files/{sha}"), (input.bytes.clone(), entry));
            attachments.push(Attachment {
                sha256: sha,
                name,
                media_type: media,
            });
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    let listed: Vec<Value> = files
        .iter()
        .map(|(path, (bytes, extra))| {
            let mut entry = Map::new();
            entry.insert("path".to_owned(), json!(path));
            entry.insert("sha256".to_owned(), json!(sha256_hex(bytes)));
            entry.extend(extra.clone());
            Value::Object(entry)
        })
        .collect();
    let mut manifest = json!({"$type": BUNDLE_TYPE, "version": 1, "files": listed});
    if let Some(produced_by) = &options.produced_by {
        manifest["produced_by"] = produced_by.clone();
    }
    if let Some(published_at) = &options.published_at {
        manifest["published_at"] = json!(published_at);
    }
    if let Some((id, stream)) = &options.feed {
        manifest["feed"] = json!({"id": id, "stream": stream});
    }
    let manifest_bytes = canonical_record(&manifest);
    let signature = options
        .signer
        .map(|key| sign::sign(key, Context::Manifest, &manifest_bytes).to_bytes());
    let stored: BTreeMap<&str, &[u8]> = files
        .iter()
        .map(|(path, (bytes, _))| (path.as_str(), bytes.as_slice()))
        .collect();
    let zip = write_zip(&manifest_bytes, &stored, signature.as_deref())?;
    Ok(Packed {
        zip,
        manifest,
        attachments,
    })
}

/// Writes the zip: the manifest, the files in path order, then the
/// signature. The same entries and options every time, so the same inputs
/// give the same bytes.
fn write_zip(
    manifest_bytes: &[u8],
    files: &BTreeMap<&str, &[u8]>,
    signature: Option<&[u8]>,
) -> Result<Vec<u8>, Vec<String>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(DateTime::default());
    let mut write = |path: &str, bytes: &[u8]| -> Result<(), String> {
        writer
            .start_file(path, options)
            .and_then(|()| writer.write_all(bytes).map_err(Into::into))
            .map_err(|e| format!("{path}: {e}"))
    };
    write(MANIFEST, manifest_bytes).map_err(|e| vec![e])?;
    for (path, bytes) in files {
        write(path, bytes).map_err(|e| vec![e])?;
    }
    if let Some(signature) = signature {
        write(SIGNATURE, signature).map_err(|e| vec![e])?;
    }
    Ok(writer
        .finish()
        .map_err(|e| vec![format!("zip: {e}")])?
        .into_inner())
}

/// Adds `manifest.sig` to a bundle's zip, signing its manifest as stored.
/// Everything else is written as [`pack`] writes it. A bundle that already
/// has a signature is refused: sign the bundle once, or pack it again.
pub fn add_signature(zip: &[u8], key: &SigningKey, limits: Limits) -> Result<Vec<u8>, Vec<String>> {
    let opened = open(zip, limits)?;
    if opened.signature.is_some() {
        return Err(vec![format!("{SIGNATURE}: the bundle is already signed")]);
    }
    let signature = sign::sign(key, Context::Manifest, &opened.manifest_bytes).to_bytes();
    let files: BTreeMap<&str, &[u8]> = opened
        .files
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect();
    write_zip(&opened.manifest_bytes, &files, Some(&signature))
}

/// Checks a bundle's signature against what the reader trusts, as
/// [`check_signed`] does for `manifest.sig` over the stored manifest.
///
/// This checks the signature only; run [`verify`] for the bundle's own checks.
pub fn check_signature(
    bundle: &Opened,
    trust: &Trust,
    expected_publisher: Option<&str>,
) -> Result<SignatureStatus, Code> {
    check_signed(
        bundle.signature.as_deref(),
        Context::Manifest,
        &bundle.manifest_bytes,
        trust,
        expected_publisher,
    )
}

/// Checks a signature file (`manifest.sig` or `feed.sig`) over `message`
/// against what the reader trusts, in this order: the signature file parses
/// and its `alg` is known; its publisher is `expected_publisher`, when given;
/// its key is known and not revoked (at any date: a revoked key's signatures
/// never verify); the signature verifies. A retired key still verifies.
///
/// No signature is [`SignatureStatus::Unverified`], unless the reader
/// trusts a key of `expected_publisher`, pinned or approved or from a key
/// set it holds: then it is `unsigned_from_pinned_publisher`.
pub fn check_signed(
    signature: Option<&[u8]>,
    context: Context,
    message: &[u8],
    trust: &Trust,
    expected_publisher: Option<&str>,
) -> Result<SignatureStatus, Code> {
    let Some(bytes) = signature else {
        return match expected_publisher {
            Some(publisher) if trust.trusts_publisher(publisher) => {
                Err(Code::UnsignedFromPinnedPublisher)
            }
            _ => Ok(SignatureStatus::Unverified),
        };
    };
    let file = SignatureFile::parse(bytes)?;
    if expected_publisher.is_some_and(|publisher| publisher != file.publisher) {
        return Err(Code::PublisherMismatch);
    }
    let Lookup::Found(key, state) = trust.lookup(&file.publisher, &file.key) else {
        return Err(Code::UnknownKey);
    };
    if state == KeyState::Revoked {
        return Err(Code::RevokedKey);
    }
    sign::verify(&key, context, message, &file)?;
    Ok(SignatureStatus::Verified {
        publisher: file.publisher,
        key: file.key,
    })
}

/// True for a path a bundle may hold: relative, `/`-separated, with no
/// empty, `.` or `..` segments and no backslashes or drive letters.
pub fn is_safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains(':')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// Reads a bundle's zip, refusing unsafe paths, duplicates, and more files
/// or bytes than `limits` allow. Directories are ignored.
pub fn open(zip: &[u8], limits: Limits) -> Result<Opened, Vec<String>> {
    let mut archive =
        ZipArchive::new(Cursor::new(zip)).map_err(|e| vec![format!("not a zip file: {e}")])?;
    // The zip reader keeps one entry per name and drops the rest, so repeats
    // would never reach the check below: two entries named manifest.json or
    // manifest.sig must not let a reader and a signer see different files.
    if archive.has_duplicate_names() {
        return Err(vec![
            "a file name appears twice in the zip's central directory".to_owned(),
        ]);
    }
    if archive.len() > limits.max_files {
        return Err(vec![format!(
            "the bundle holds {} entries; the limit is {}",
            archive.len(),
            limits.max_files
        )]);
    }
    let mut problems = Vec::new();
    let mut files = BTreeMap::new();
    let mut total: u64 = 0;
    for index in 0..archive.len() {
        let entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(e) => {
                problems.push(format!("entry {index}: {e}"));
                continue;
            }
        };
        if entry.is_dir() {
            continue;
        }
        let path = match entry.name() {
            Ok(name) => name.into_owned(),
            Err(e) => {
                problems.push(format!("entry {index}: {e}"));
                continue;
            }
        };
        if !is_safe_path(&path) {
            problems.push(format!("{path}: not a safe path inside a bundle"));
            continue;
        }
        let remaining = limits.max_total_bytes.saturating_sub(total);
        let mut bytes = Vec::new();
        let read = entry.take(remaining + 1).read_to_end(&mut bytes);
        if let Err(e) = read {
            problems.push(format!("{path}: {e}"));
            continue;
        }
        total += bytes.len() as u64;
        if total > limits.max_total_bytes {
            return Err(vec![format!(
                "the bundle's contents exceed {} bytes",
                limits.max_total_bytes
            )]);
        }
        if files.insert(path.clone(), bytes).is_some() {
            problems.push(format!("{path}: appears twice"));
        }
    }
    let signature = files.remove(SIGNATURE);
    let Some(manifest_bytes) = files.remove(MANIFEST) else {
        problems.push(format!("no {MANIFEST}"));
        return Err(problems);
    };
    let manifest = match serde_json::from_slice::<Value>(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(e) => {
            problems.push(format!("{MANIFEST}: not JSON: {e}"));
            return Err(problems);
        }
    };
    if problems.is_empty() {
        Ok(Opened {
            manifest,
            manifest_bytes,
            signature,
            files,
        })
    } else {
        Err(problems)
    }
}

/// Checks an opened bundle: the manifest's type, every hash, that the
/// manifest lists exactly the files present, that each record's type
/// matches its listing, and that references resolve. Record references are
/// checked for types whose schema is among `schemas` (expanded schemas,
/// matched by their `$type` and `version` consts); attachment references
/// always are.
pub fn verify(bundle: &Opened, schemas: &[Value]) -> Report {
    let mut report = Report::default();
    let problems = &mut report.problems;
    let manifest = &bundle.manifest;
    if manifest.get("$type") != Some(&json!(BUNDLE_TYPE))
        || manifest.get("version") != Some(&json!(1))
    {
        problems.push(format!(
            "{MANIFEST}: not an {BUNDLE_TYPE} version 1 manifest"
        ));
    }
    let Some(listed) = manifest.get("files").and_then(Value::as_array) else {
        problems.push(format!("{MANIFEST}: no files list"));
        return report;
    };
    let mut seen = BTreeSet::new();
    let mut records: BTreeMap<String, Value> = BTreeMap::new();
    for entry in listed {
        let (Some(path), Some(sha)) = (
            entry.get("path").and_then(Value::as_str),
            entry.get("sha256").and_then(Value::as_str),
        ) else {
            problems.push(format!("{MANIFEST}: an entry without path or sha256"));
            continue;
        };
        if !seen.insert(path.to_owned()) {
            problems.push(format!("{MANIFEST}: {path} is listed twice"));
        }
        let Some(bytes) = bundle.files.get(path) else {
            problems.push(format!("{path}: listed but missing"));
            continue;
        };
        if sha256_hex(bytes) != sha {
            problems.push(format!("{path}: SHA-256 doesn't match the manifest"));
        }
        if let Some(kind) = entry.get("record_type").and_then(Value::as_str) {
            match serde_json::from_slice::<Value>(bytes) {
                Ok(record) => {
                    let version = entry.get("record_version").and_then(Value::as_u64);
                    if record_type(&record) != version.map(|v| (kind, v)) {
                        problems.push(format!(
                            "{path}: its $type and version don't match the manifest"
                        ));
                    }
                    // The folder is the type's title, which only its schema gives.
                    let version = version.unwrap_or_default();
                    let folder =
                        schema_for(schemas, kind, version).map(|_| kind_of(schemas, kind, version));
                    let placed = path
                        .strip_prefix("records/")
                        .and_then(|rest| rest.strip_suffix(".json"))
                        .and_then(|rest| rest.split_once('/'))
                        .is_some_and(|(found, key)| {
                            is_key(key) && folder.as_deref().map_or(true, |f| f == found)
                        });
                    if !placed {
                        let folder = folder.unwrap_or_else(|| "<kind>".to_owned());
                        problems.push(format!(
                            "{path}: a {kind} record belongs at records/{folder}/<id>.json"
                        ));
                    }
                    records.insert(path.to_owned(), record);
                }
                Err(e) => problems.push(format!("{path}: not JSON: {e}")),
            }
        }
    }
    for path in bundle.files.keys() {
        if !seen.contains(path) {
            problems.push(format!("{path}: present but not listed in {MANIFEST}"));
        }
    }
    let keys: BTreeSet<(String, String)> = records
        .keys()
        .filter_map(|path| {
            let rest = path.strip_prefix("records/")?.strip_suffix(".json")?;
            let (kind, key) = rest.split_once('/')?;
            Some((kind.to_owned(), key.to_owned()))
        })
        .collect();
    let mut unchecked = BTreeSet::new();
    for (path, record) in &records {
        let mut found = Vec::new();
        attachment_refs(record, &mut found);
        for sha in found {
            if !bundle.files.contains_key(&format!("files/{sha}")) {
                problems.push(format!(
                    "{path}: refers to attachment {sha}, which isn't in the bundle"
                ));
            }
        }
        let Some((kind, version)) = record_type(record) else {
            continue;
        };
        let schema = schema_for(schemas, kind, version);
        let Some(schema) = schema else {
            unchecked.insert(format!("{kind} v{version}"));
            continue;
        };
        let mut refs = Vec::new();
        record_refs(schema, schema, record, &mut refs, 0);
        for (kinds, reference) in refs {
            let target = reference.split('#').next().unwrap_or(&reference);
            let resolved = target.split_once(':').is_some_and(|(kind, key)| {
                (kinds.is_empty() || kinds.iter().any(|k| k == kind))
                    && keys.contains(&(kind.to_owned(), key.to_owned()))
            });
            if !resolved {
                problems.push(format!(
                    "{path}: refers to {reference}, which isn't in the bundle"
                ));
            }
        }
    }
    report.unchecked_types = unchecked.into_iter().collect();
    report
}

/// Collects the SHA-256 of every attachment reference in a record: an
/// object with `sha256`, `name` and `media_type`.
fn attachment_refs(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let (Some(Value::String(sha)), true, true) = (
                map.get("sha256"),
                map.contains_key("name"),
                map.contains_key("media_type"),
            ) {
                out.push(sha.clone());
            }
            map.values().for_each(|v| attachment_refs(v, out));
        }
        Value::Array(items) => items.iter().for_each(|v| attachment_refs(v, out)),
        _ => {}
    }
}

/// Collects `(allowed kinds, reference)` for every string in `value` that
/// `node` marks as a reference with the short form's `ref` annotation.
/// Follows `$ref`s within the schema; other schemas only define the string
/// pattern, so they aren't followed.
fn record_refs(
    root: &Value,
    node: &Value,
    value: &Value,
    out: &mut Vec<(Vec<String>, String)>,
    depth: usize,
) {
    if depth > 64 {
        return;
    }
    let Some(node) = node.as_object() else { return };
    if let Some(target) = node.get("$ref").and_then(Value::as_str) {
        if let Some(name) = target.strip_prefix("#/$defs/") {
            if let Some(def) = root.get("$defs").and_then(|d| d.get(name)) {
                record_refs(root, def, value, out, depth + 1);
            }
        }
    }
    if let (Some(kinds), Value::String(text)) = (node.get("ref"), value) {
        let kinds = match kinds {
            Value::String(kind) => vec![kind.clone()],
            Value::Array(list) => list
                .iter()
                .filter_map(|k| k.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        };
        out.push((kinds, text.clone()));
    }
    if let (Some(Value::Object(properties)), Value::Object(fields)) =
        (node.get("properties"), value)
    {
        for (name, field) in fields {
            if let Some(schema) = properties.get(name) {
                record_refs(root, schema, field, out, depth + 1);
            }
        }
    }
    if let (Some(items), Value::Array(list)) = (node.get("items"), value) {
        for item in list {
            record_refs(root, items, item, out, depth + 1);
        }
    }
    if let Some(Value::Array(branches)) = node.get("anyOf") {
        for branch in branches {
            record_refs(root, branch, value, out, depth + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control() -> Input {
        Input {
            name: "mfa.json".to_owned(),
            bytes: br#"{"$type":"tech.monorail.controls.control","version":1,"id":"mfa","title":"MFA"}"#.to_vec(),
        }
    }

    fn statement(reference: &str, evidence_sha: &str) -> Input {
        Input {
            name: "s1.json".to_owned(),
            bytes: serde_json::to_vec(&json!({
                "$type": "tech.monorail.controls.statement",
                "version": 1,
                "id": "s1",
                "controls": [reference],
                "evidence": {"sha256": evidence_sha, "name": "review.pdf", "media_type": "application/pdf"}
            }))
            .unwrap(),
        }
    }

    fn statement_schema() -> Value {
        json!({
            "$id": "https://example.org/schemas/tech.monorail.controls.statement/v1.json",
            "type": "object",
            "properties": {
                "$type": {"const": "tech.monorail.controls.statement"},
                "version": {"const": 1},
                "controls": {"type": "array", "items": {"$ref": "x#/$defs/refString", "ref": "control"}}
            }
        })
    }

    fn evidence() -> Input {
        Input {
            name: "review.pdf".to_owned(),
            bytes: b"%PDF-1.4 invented".to_vec(),
        }
    }

    #[test]
    fn packs_opens_and_verifies() {
        let sha = sha256_hex(&evidence().bytes);
        let packed = pack(
            &[control(), statement("control:mfa", &sha), evidence()],
            &[],
            Some(json!({"app": "test"})),
        )
        .unwrap();
        let again = pack(
            &[evidence(), statement("control:mfa", &sha), control()],
            &[],
            Some(json!({"app": "test"})),
        )
        .unwrap();
        assert_eq!(packed.zip, again.zip, "same inputs, same bytes");
        let opened = open(&packed.zip, Limits::default()).unwrap();
        let paths: Vec<&String> = opened.files.keys().collect();
        assert_eq!(
            paths,
            vec![
                &format!("files/{sha}"),
                &"records/control/mfa.json".to_owned(),
                &"records/statement/s1.json".to_owned()
            ]
        );
        let report = verify(&opened, &[statement_schema()]);
        assert_eq!(report.problems, Vec::<String>::new());
        assert_eq!(
            report.unchecked_types,
            vec!["tech.monorail.controls.control v1"]
        );
    }

    #[test]
    fn finds_broken_references_and_tampering() {
        let packed = pack(
            &[control(), statement("control:sso", &"0".repeat(64))],
            &[],
            None,
        )
        .unwrap();
        let mut opened = open(&packed.zip, Limits::default()).unwrap();
        opened.files.insert("extra.txt".to_owned(), b"x".to_vec());
        opened
            .files
            .get_mut("records/control/mfa.json")
            .unwrap()
            .push(b' ');
        let problems = verify(&opened, &[statement_schema()]).problems;
        assert!(
            problems.iter().any(|p| p.contains("SHA-256 doesn't match")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("extra.txt: present but not listed")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("refers to control:sso")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("refers to attachment 0000")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_schema_title_names_the_folder() {
        let mut schema = statement_schema();
        schema["title"] = json!("control-statement");
        let sha = sha256_hex(&evidence().bytes);
        let inputs = [control(), statement("control:mfa", &sha), evidence()];
        let packed = pack(&inputs, &[schema.clone()], None).unwrap();
        let opened = open(&packed.zip, Limits::default()).unwrap();
        assert!(opened
            .files
            .contains_key("records/control-statement/s1.json"));
        assert_eq!(verify(&opened, &[schema]).problems, Vec::<String>::new());
        assert_eq!(verify(&opened, &[]).problems, Vec::<String>::new());
        let mut wrong = statement_schema();
        wrong["title"] = json!("other");
        let problems = verify(&opened, &[wrong]).problems;
        assert!(
            problems
                .iter()
                .any(|p| p.contains("belongs at records/other/")),
            "{problems:?}"
        );
    }

    #[test]
    fn refuses_unsafe_paths() {
        for path in ["../evil", "/etc/passwd", "a/../b", "c:\\x", "a//b", "./a"] {
            assert!(!is_safe_path(path), "{path}");
        }
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("../evil", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"x").unwrap();
        let zip = writer.finish().unwrap().into_inner();
        let problems = open(&zip, Limits::default()).unwrap_err();
        assert!(problems[0].contains("not a safe path"), "{problems:?}");
    }

    #[test]
    fn refuses_oversized_contents() {
        let packed = pack(
            &[Input {
                name: "big.bin".to_owned(),
                bytes: vec![0; 10_000],
            }],
            &[],
            None,
        )
        .unwrap();
        let limits = Limits {
            max_files: 10,
            max_total_bytes: 1_000,
        };
        assert!(open(&packed.zip, limits).unwrap_err()[0].contains("exceed"));
    }
}
