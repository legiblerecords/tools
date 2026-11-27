//! Runs the spec's test vectors (copied into tests/vectors from
//! legiblerecords/spec; see tests/vectors/SOURCE).

use legible_records::short_form::{expand, generate, Options};
use legible_records::validate::Schemas;
use legible_records::yaml::parse_restricted;
use serde_json::{json, Value};

fn load(name: &str) -> Vec<Value> {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let file: Value = serde_json::from_str(&text).expect("vectors are JSON");
    file["cases"].as_array().expect("cases").clone()
}

fn options(case: &Value) -> Options {
    let mut options = Options::default();
    if let Some(given) = case.get("options") {
        if let Some(common) = given.get("common").and_then(Value::as_str) {
            options.common = common.to_owned();
        }
        if let Some(location) = given.get("location").and_then(Value::as_str) {
            options.location = location.to_owned();
        }
        if let Some(base) = given.get("base").and_then(Value::as_str) {
            options.base = Some(base.to_owned());
        }
    }
    options
}

fn run_schema_language(file: &str) {
    let mut failures = Vec::new();
    let cases = load(file);
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let schema = case["schema"].as_str().unwrap();
        let options = options(case);
        let expect = &case["expect"];
        if let Some(short) = case.get("short").and_then(Value::as_str) {
            let got = match expand(short, schema, &options) {
                Ok(body) => json!({"body": body}),
                Err(problems) => json!({"problems": problems
                    .iter()
                    .map(|p| json!({"line": p.line, "path": p.path, "message": p.message}))
                    .collect::<Vec<_>>()}),
            };
            if &got != expect {
                failures.push(format!("{name}:\n  expected {expect}\n  got      {got}"));
            }
        } else {
            let body = &case["body"];
            match generate(body, schema, &options) {
                Ok(short) if Some(short.as_str()) == expect["short"].as_str() => {}
                Ok(short) => failures.push(format!(
                    "{name}:\n  expected {:?}\n  got      {short:?}",
                    expect["short"].as_str().unwrap_or_default()
                )),
                Err(error) => failures.push(format!("{name}: {error}")),
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases in {file} failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

#[test]
fn schema_language() {
    run_schema_language("schema-language.json");
}

#[test]
fn schema_language_published() {
    run_schema_language("schema-language-published.json");
}

#[test]
fn restricted_yaml() {
    let mut failures = Vec::new();
    for case in load("restricted-yaml.json") {
        let name = case["name"].as_str().unwrap();
        let got = match parse_restricted(case["yaml"].as_str().unwrap()) {
            Ok(value) => json!({"value": value}),
            Err(error) => json!({"error": error.reason}),
        };
        if got != case["expect"] {
            failures.push(format!("{name}: expected {} got {got}", case["expect"]));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn generation_round_trips() {
    // Every expected body generates a short form that expands back to the
    // same normal form.
    for file in ["schema-language.json", "schema-language-published.json"] {
        for case in load(file) {
            let Some(body) = case["expect"].get("body") else {
                continue;
            };
            let schema = case["schema"].as_str().unwrap();
            let options = options(&case);
            let short = generate(body, schema, &options).unwrap();
            let back = expand(&short, schema, &options)
                .unwrap_or_else(|p| panic!("{}: {short}\n{p:?}", case["name"]));
            assert_eq!(
                legible_records::short_form::normalize(&back),
                legible_records::short_form::normalize(body),
                "{}: {short}",
                case["name"]
            );
        }
    }
}

/// `schema` without its rule members: each `allOf` entry with `x-rule`
/// taken out, and an `allOf` that empties dropped.
fn without_rules(schema: &Value) -> Value {
    match schema {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, value) in map {
                if key == "allOf" {
                    if let Value::Array(entries) = value {
                        let kept: Vec<Value> = entries
                            .iter()
                            .filter(|e| e.get("x-rule").is_none())
                            .map(without_rules)
                            .collect();
                        if !kept.is_empty() {
                            out.insert(key.clone(), Value::Array(kept));
                        }
                        continue;
                    }
                }
                out.insert(key.clone(), without_rules(value));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(without_rules).collect()),
        other => other.clone(),
    }
}

#[test]
fn rules_vectors() {
    // Each record's failures are the type's own, then exactly the rule
    // failures the vector lists, in order.
    let mut failures = Vec::new();
    let cases = load("rules.json");
    let mut records = 0;
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let options = options(case);
        let mut schema = expand(case["short"].as_str().unwrap(), "t", &options)
            .unwrap_or_else(|p| panic!("{name}: {p:?}"));
        if schema.get("$id").is_none() {
            schema["$id"] = json!("https://example.org/t.json");
        }
        let schemas = Schemas::default();
        let own_schema = without_rules(&schema);
        for (n, entry) in case["records"].as_array().unwrap().iter().enumerate() {
            records += 1;
            let record = &entry["record"];
            let own = schemas.validate(&own_schema, record).unwrap();
            let got = schemas
                .validate(&schema, record)
                .unwrap_or_else(|e| panic!("{name} record {n}: {e}"));
            let mut want: Vec<Value> = own
                .iter()
                .map(|f| json!({"pointer": f.pointer, "message": f.message}))
                .collect();
            want.extend(entry["failures"].as_array().unwrap().iter().cloned());
            let got: Vec<Value> = got
                .iter()
                .map(|f| json!({"pointer": f.pointer, "message": f.message}))
                .collect();
            if got != want {
                failures.push(format!(
                    "{name} record {n}:\n  expected {}\n  got      {}",
                    Value::from(want),
                    Value::from(got)
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {records} records in rules.json failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
