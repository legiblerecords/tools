//! WebAssembly bindings for `legible-records`, published to npm as
//! `@legiblerecords/legible`.
//!
//! Values cross into JavaScript as plain JSON-compatible objects and
//! arrays. Record validation isn't included: JavaScript has good JSON Schema
//! validators (such as Ajv), and the expanded schemas are standard JSON
//! Schema 2020-12.

use legible_records::code::Code;
use legible_records::keys::{parse_pin, parse_pin_text, KeySet, Trust};
use legible_records::short_form::{self, Options};
use legible_records::sign::{self, SignatureFile, SigningKey};
use legible_records::{bundle, compat, lint, time, yaml};
use serde::Serialize;
use serde_json::Value;
use wasm_bindgen::prelude::*;

fn to_js<T: Serialize + ?Sized>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsError::new(&e.to_string()))
}

fn from_js(value: JsValue, what: &str) -> Result<Value, JsError> {
    serde_wasm_bindgen::from_value(value).map_err(|e| JsError::new(&format!("{what}: {e}")))
}

/// Reads `{ base?, common?, location? }`. A `base` makes the options those of
/// a published type, whose shared names point at org.legiblerecords.common.
fn options(value: JsValue) -> Result<Options, JsError> {
    if value.is_undefined() || value.is_null() {
        return Ok(Options::default());
    }
    let value = from_js(value, "options")?;
    let text = |key: &str| -> Result<Option<String>, JsError> {
        match value.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) => Ok(Some(text.clone())),
            Some(_) => Err(JsError::new(&format!("options.{key} must be a string"))),
        }
    };
    let mut options = match text("base")? {
        Some(base) => Options::published(&base),
        None => Options::default(),
    };
    if let Some(common) = text("common")? {
        options.common = common;
    }
    if let Some(location) = text("location")? {
        options.location = location;
    }
    Ok(options)
}

#[derive(Serialize)]
struct Problem<'a> {
    line: usize,
    path: &'a str,
    message: &'a str,
}

#[derive(Serialize)]
struct Located<'a> {
    pointer: &'a str,
    message: &'a str,
}

/// Expands a short-form schema. Returns `{ ok: true, body }`, or
/// `{ ok: false, problems: [{ line, path, message }] }` with every problem
/// in the file.
#[wasm_bindgen]
pub fn expand(text: &str, name: &str, options_value: JsValue) -> Result<JsValue, JsError> {
    let options = options(options_value)?;
    match short_form::expand(text, name, &options) {
        Ok(body) => to_js(&serde_json::json!({"ok": true, "body": body})),
        Err(problems) => {
            let problems: Vec<Problem> = problems
                .iter()
                .map(|p| Problem {
                    line: p.line,
                    path: &p.path,
                    message: &p.message,
                })
                .collect();
            #[derive(Serialize)]
            struct Failed<'a> {
                ok: bool,
                problems: Vec<Problem<'a>>,
            }
            to_js(&Failed {
                ok: false,
                problems,
            })
        }
    }
}

/// Generates the canonical short form of a JSON Schema body. Throws when the
/// body isn't an object.
#[wasm_bindgen]
pub fn generate(body: JsValue, name: &str, options_value: JsValue) -> Result<String, JsError> {
    let options = options(options_value)?;
    let body = from_js(body, "body")?;
    short_form::generate(&body, name, &options).map_err(|e| JsError::new(&e))
}

/// The JSON normal form of a schema body: what expanding its generated short
/// form gives back.
#[wasm_bindgen]
pub fn normalize(body: JsValue) -> Result<JsValue, JsError> {
    to_js(&short_form::normalize(&from_js(body, "body")?))
}

/// Checks an expanded schema against the published subset. Returns
/// `[{ pointer, message }]`, empty when it passes.
#[wasm_bindgen]
pub fn lint(schema: JsValue) -> Result<JsValue, JsError> {
    let findings = lint::lint(&from_js(schema, "schema")?);
    let out: Vec<Located> = findings
        .iter()
        .map(|f| Located {
            pointer: &f.pointer,
            message: &f.message,
        })
        .collect();
    to_js(&out)
}

/// Lists the changes from `old` to `new` that break compatibility within a
/// major version. Returns `[{ pointer, message }]`, empty when compatible.
#[wasm_bindgen(js_name = checkCompat)]
pub fn check_compat(old: JsValue, new: JsValue) -> Result<JsValue, JsError> {
    let breaks = compat::check(&from_js(old, "old")?, &from_js(new, "new")?);
    let out: Vec<Located> = breaks
        .iter()
        .map(|b| Located {
            pointer: &b.pointer,
            message: &b.message,
        })
        .collect();
    to_js(&out)
}

/// Parses restricted YAML. Returns `{ ok: true, value }`, or
/// `{ ok: false, error: { reason, line, col, message } }`.
#[wasm_bindgen(js_name = parseYaml)]
pub fn parse_yaml(text: &str) -> Result<JsValue, JsError> {
    match yaml::parse_restricted(text) {
        Ok(value) => to_js(&serde_json::json!({"ok": true, "value": value})),
        Err(error) => to_js(&serde_json::json!({
            "ok": false,
            "error": {
                "reason": error.reason,
                "line": error.line,
                "col": error.col,
                "message": error.message,
            }
        })),
    }
}

/// The bundled `org.legiblerecords.common` version 1 schema.
#[wasm_bindgen(js_name = commonSchema)]
pub fn common_schema() -> Result<JsValue, JsError> {
    let common: Value = serde_json::from_str(legible_records::COMMON_V1)
        .expect("the bundled common schema is JSON");
    to_js(&common)
}

fn schema_list(schemas: JsValue) -> Result<Vec<Value>, JsError> {
    if schemas.is_undefined() || schemas.is_null() {
        return Ok(Vec::new());
    }
    match from_js(schemas, "schemas")? {
        Value::Array(list) => Ok(list),
        _ => Err(JsError::new("schemas must be an array")),
    }
}

fn problems_error(problems: &[String]) -> JsError {
    JsError::new(&problems.join("\n"))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    /// JavaScript's `Date.now()`: WebAssembly has no clock of its own.
    #[wasm_bindgen(js_namespace = Date, js_name = now)]
    fn date_now() -> f64;
}

/// The current instant, from the host's clock on WebAssembly.
fn now() -> time::Instant {
    #[cfg(target_arch = "wasm32")]
    {
        time::from_unix_millis(date_now() as i64)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        time::now()
    }
}

/// Makes a signing key for a publisher (a lowercase domain) and a key id.
/// Returns `{ secretKey: Uint8Array, keySetEntry }`: the secret key file's
/// bytes, to be kept private, and the entry to add to the publisher's
/// keys.json.
#[wasm_bindgen(js_name = generateKey)]
pub fn generate_key(publisher: &str, id: &str) -> Result<JsValue, JsError> {
    let key = SigningKey::generate(publisher, id).map_err(|e| JsError::new(&e))?;
    let entry = serde_json::json!({
        "id": key.id,
        "alg": "ed25519",
        "public_key": sign::b64url(&key.public().key),
        "created_at": time::format(now()),
    });
    let secret = key.to_json();
    let out = js_sys::Object::new();
    let secret_key = js_sys::Uint8Array::from(secret.as_slice());
    js_sys::Reflect::set(&out, &"secretKey".into(), &secret_key)
        .and_then(|_| js_sys::Reflect::set(&out, &"keySetEntry".into(), &to_js(&entry)?))
        .map_err(|_| JsError::new("couldn't build the result"))?;
    Ok(out.into())
}

/// Signs a bundle's manifest as stored, returning the bundle's bytes with
/// `manifest.sig` added. `secretKey` is the file `generateKey` returned.
/// Throws when the bundle has problems or is already signed.
#[wasm_bindgen(js_name = signBundle)]
pub fn sign_bundle(zip: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let key = SigningKey::from_json(secret_key).map_err(|e| JsError::new(&e))?;
    bundle::add_signature(zip, &key, bundle::Limits::default()).map_err(|p| problems_error(&p))
}

/// Checks a record set's bytes against its manifest entry, `{ recordType,
/// recordVersion, count, sha256 }`, and returns its records. Throws with the
/// first problem, naming its line.
#[wasm_bindgen(js_name = recordSet)]
pub fn record_set(bytes: &[u8], expect: JsValue) -> Result<JsValue, JsError> {
    let expect = from_js(expect, "expect")?;
    let field = |key: &str| {
        expect
            .get(key)
            .ok_or_else(|| JsError::new(&format!("expect.{key} is missing")))
    };
    let (Some(record_type), Some(record_version), Some(count), Some(sha256)) = (
        field("recordType")?.as_str(),
        field("recordVersion")?.as_u64(),
        field("count")?.as_u64(),
        field("sha256")?.as_str(),
    ) else {
        return Err(JsError::new(
            "expect needs recordType and sha256 strings, and recordVersion and count integers",
        ));
    };
    let records = legible_records::record_set::check(
        bytes,
        legible_records::record_set::Expect {
            record_type,
            record_version,
            count,
            sha256,
        },
    )
    .map_err(|p| problems_error(&p))?;
    to_js(&records)
}

/// Builds a bundle: `add` each file, then `finish`. A `.json` file with
/// `$type` and `version` becomes a record; anything else an attachment.
#[wasm_bindgen]
#[derive(Default)]
pub struct BundleBuilder {
    inputs: Vec<bundle::Input>,
    sets: bundle::SetMode,
}

#[wasm_bindgen]
impl BundleBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> BundleBuilder {
        BundleBuilder::default()
    }

    /// Adds a file by its name and bytes. A `.ndjson` file is a record set
    /// and is packed as it is.
    pub fn add(&mut self, name: String, bytes: Vec<u8>) {
        self.inputs.push(bundle::Input { name, bytes });
    }

    /// Writes these kinds as record sets, whatever their size.
    #[wasm_bindgen(js_name = setKinds)]
    pub fn set_kinds(&mut self, kinds: Vec<String>) {
        self.sets = bundle::SetMode::Kinds(kinds);
    }

    /// Writes every record as its own file (`.ndjson` inputs stay sets).
    #[wasm_bindgen(js_name = noSets)]
    pub fn no_sets(&mut self) {
        self.sets = bundle::SetMode::Never;
    }

    /// Packs the files. `schemas` (expanded, optional) give each record's
    /// folder, its type's title; without one it's the type's last segment.
    /// Throws with every problem, one per line.
    pub fn finish(&self, schemas: JsValue, produced_by: JsValue) -> Result<PackedBundle, JsError> {
        let schemas = schema_list(schemas)?;
        let produced_by = if produced_by.is_undefined() || produced_by.is_null() {
            None
        } else {
            Some(from_js(produced_by, "producedBy")?)
        };
        let options = bundle::PackOptions {
            produced_by,
            sets: self.sets.clone(),
            ..bundle::PackOptions::default()
        };
        let packed =
            bundle::pack_with(&self.inputs, &schemas, &options).map_err(|p| problems_error(&p))?;
        Ok(PackedBundle { packed })
    }
}

/// A packed bundle: its zip, its manifest, and its attachments as records
/// refer to them.
#[wasm_bindgen]
pub struct PackedBundle {
    packed: bundle::Packed,
}

#[wasm_bindgen]
impl PackedBundle {
    /// The zip's bytes.
    pub fn zip(&self) -> Vec<u8> {
        self.packed.zip.clone()
    }

    /// The manifest.
    pub fn manifest(&self) -> Result<JsValue, JsError> {
        to_js(&self.packed.manifest)
    }

    /// `[{ sha256, name, media_type }]`, for referring to the attachments from records.
    pub fn attachments(&self) -> Result<JsValue, JsError> {
        let list: Vec<Value> = self
            .packed
            .attachments
            .iter()
            .map(|a| serde_json::json!({"sha256": a.sha256, "name": a.name, "media_type": a.media_type}))
            .collect();
        to_js(&list)
    }
}

/// An opened bundle. `Bundle.open` refuses unsafe paths, duplicates, and
/// more than 10,000 files or 1 GiB of contents.
#[wasm_bindgen]
pub struct Bundle {
    opened: bundle::Opened,
}

#[wasm_bindgen]
impl Bundle {
    /// Opens a bundle's zip. Throws with every problem, one per line.
    pub fn open(zip: &[u8]) -> Result<Bundle, JsError> {
        let opened =
            bundle::open(zip, bundle::Limits::default()).map_err(|p| problems_error(&p))?;
        Ok(Bundle { opened })
    }

    /// The manifest.
    pub fn manifest(&self) -> Result<JsValue, JsError> {
        to_js(&self.opened.manifest)
    }

    /// Every path in the bundle except the manifest, sorted.
    pub fn paths(&self) -> Vec<String> {
        self.opened.files.keys().cloned().collect()
    }

    /// A file's bytes, or `undefined`.
    pub fn file(&self, path: &str) -> Option<Vec<u8>> {
        self.opened.files.get(path).cloned()
    }

    /// The bundle's record sets: `[{ path, recordType, recordVersion, count }]`.
    #[wasm_bindgen(js_name = recordSets)]
    pub fn record_sets(&self) -> Result<JsValue, JsError> {
        let sets: Vec<Value> = self
            .opened
            .manifest
            .get("files")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|f| {
                f.get("path")
                    .and_then(Value::as_str)
                    .and_then(legible_records::record_set::kind_of_path)
                    .is_some()
            })
            .map(|f| {
                serde_json::json!({
                    "path": f["path"],
                    "recordType": f["record_type"],
                    "recordVersion": f["record_version"],
                    "count": f["count"],
                })
            })
            .collect();
        to_js(&sets)
    }

    /// The manifest's bytes exactly as stored: what a signature covers.
    #[wasm_bindgen(js_name = manifestBytes)]
    pub fn manifest_bytes(&self) -> Vec<u8> {
        self.opened.manifest_bytes.clone()
    }

    /// `manifest.sig`'s bytes exactly as stored, or `undefined` for an
    /// unsigned bundle.
    pub fn signature(&self) -> Option<Vec<u8>> {
        self.opened.signature.clone()
    }

    /// Checks hashes, the file list and references, and that `published_at`
    /// is no more than 24 hours after the reader's clock: `nowMillis` (Unix
    /// milliseconds), or the host's `Date.now()` when it is omitted.
    /// `schemas` are expanded schemas; record references are checked for the
    /// types among them. Returns `{ problems: string[], uncheckedTypes:
    /// string[] }`.
    pub fn verify(&self, schemas: JsValue, now_millis: Option<f64>) -> Result<JsValue, JsError> {
        let schemas = schema_list(schemas)?;
        let now = match now_millis {
            Some(millis) => time::from_unix_millis(millis as i64),
            None => now(),
        };
        let report = bundle::verify_at(&self.opened, &schemas, now);
        to_js(&serde_json::json!({
            "problems": report.problems,
            "uncheckedTypes": report.unchecked_types,
        }))
    }

    /// Checks the manifest's signature against the keys given:
    /// `{ pins?: [{ publisher, id, alg?, publicKey }], keySets?: [Uint8Array],
    /// expectedPublisher? }`, a key set being a publisher's keys.json as
    /// stored. Returns `{ status: "verified", publisher, key }` or
    /// `{ status: "unverified" }`. Throws an `Error` whose `message` is the
    /// outcome code, such as `unknown_key` or `bad_signature`.
    #[wasm_bindgen(js_name = verifySignature)]
    pub fn verify_signature(&self, options: JsValue) -> Result<JsValue, JsError> {
        let (trust, expected) = trust_options(options)?;
        match bundle::check_signature(&self.opened, &trust, expected.as_deref()) {
            Ok(bundle::SignatureStatus::Verified { publisher, key, .. }) => to_js(
                &serde_json::json!({"status": "verified", "publisher": publisher, "key": key}),
            ),
            Ok(bundle::SignatureStatus::Unverified) => {
                to_js(&serde_json::json!({"status": "unverified"}))
            }
            Err(code) => Err(code_error(code)),
        }
    }

    /// Who the manifest says signed it, without checking: `{ publisher, key }`,
    /// or `undefined` for an unsigned bundle. Throws `bad_signature_file` when
    /// manifest.sig isn't the JSON the spec defines.
    #[wasm_bindgen(js_name = signedBy)]
    pub fn signed_by(&self) -> Result<JsValue, JsError> {
        match &self.opened.signature {
            None => Ok(JsValue::UNDEFINED),
            Some(bytes) => {
                let sig = SignatureFile::parse(bytes).map_err(code_error)?;
                to_js(&serde_json::json!({"publisher": sig.publisher, "key": sig.key}))
            }
        }
    }
}

/// Reads a pin written `<publisher>/<id>=<public_key>`, as the command
/// line's `--pin` takes it. Returns `{ publisher, id, alg, publicKey }`, as
/// `verifySignature` takes pins; throws with what is wrong.
#[wasm_bindgen(js_name = parsePin)]
pub fn parse_pin_js(text: &str) -> Result<JsValue, JsError> {
    let pin = parse_pin_text(text).map_err(|e| JsError::new(&e))?;
    to_js(&serde_json::json!({
        "publisher": pin.publisher,
        "id": pin.id,
        "alg": pin.alg,
        "publicKey": sign::b64url(&pin.public_key),
    }))
}

/// Reads a key set (a publisher's keys.json, as stored) on its own, as
/// `verifySignature` would. Returns its publisher; throws an `Error` whose
/// `message` is the outcome code (`bad_key_set`).
#[wasm_bindgen(js_name = checkKeySet)]
pub fn check_key_set(bytes: &[u8]) -> Result<String, JsError> {
    KeySet::parse(bytes)
        .map(|set| set.publisher)
        .map_err(code_error)
}

fn code_error(code: Code) -> JsError {
    JsError::new(code.as_str())
}

/// Reads `{ pins?, keySets?, expectedPublisher? }`.
fn trust_options(value: JsValue) -> Result<(Trust, Option<String>), JsError> {
    let mut trust = Trust::default();
    if value.is_undefined() || value.is_null() {
        return Ok((trust, None));
    }
    let get = |name: &str| -> Result<JsValue, JsError> {
        js_sys::Reflect::get(&value, &name.into())
            .map_err(|_| JsError::new("options must be an object"))
    };
    let pins = get("pins")?;
    if !pins.is_undefined() && !pins.is_null() {
        let Value::Array(list) = from_js(pins, "pins")? else {
            return Err(JsError::new("pins must be an array"));
        };
        for p in &list {
            let text = |key: &str| {
                p.get(key)
                    .and_then(Value::as_str)
                    .ok_or_else(|| JsError::new(&format!("a pin needs a string {key}")))
            };
            let alg = match p.get("alg") {
                None | Some(Value::Null) => "ed25519",
                Some(_) => text("alg")?,
            };
            let pin = parse_pin(text("publisher")?, text("id")?, alg, text("publicKey")?)
                .map_err(|e| JsError::new(&format!("a pin's {e}")))?;
            trust.pins.push(pin);
        }
    }
    let sets = get("keySets")?;
    if !sets.is_undefined() && !sets.is_null() {
        if !js_sys::Array::is_array(&sets) {
            return Err(JsError::new("keySets must be an array"));
        }
        for set in js_sys::Array::from(&sets).iter() {
            if !set.is_instance_of::<js_sys::Uint8Array>() {
                return Err(JsError::new("a key set must be a Uint8Array of its JSON"));
            }
            let bytes = js_sys::Uint8Array::new(&set).to_vec();
            let parsed = KeySet::parse(&bytes).map_err(code_error)?;
            let publisher = parsed.publisher.clone();
            if trust.key_sets.insert(publisher.clone(), parsed).is_some() {
                return Err(JsError::new(&format!("a second key set for {publisher}")));
            }
        }
    }
    let expected = get("expectedPublisher")?;
    let expected = if expected.is_undefined() || expected.is_null() {
        None
    } else {
        Some(
            expected
                .as_string()
                .ok_or_else(|| JsError::new("expectedPublisher must be a string"))?,
        )
    };
    Ok((trust, expected))
}
