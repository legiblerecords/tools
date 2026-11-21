//! WebAssembly bindings for `legible-records`, published to npm as
//! `@legiblerecords/legible`.
//!
//! Values cross into JavaScript as plain JSON-compatible objects and
//! arrays. Record validation isn't included: JavaScript has good JSON Schema
//! validators (such as Ajv), and the expanded schemas are standard JSON
//! Schema 2020-12.

use legible_records::short_form::{self, Options};
use legible_records::{compat, lint, yaml};
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
