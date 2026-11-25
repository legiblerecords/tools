//! Content lines and content hashes (spec/records.md § Content lines), against
//! the spec's vectors/content-lines.json.

use legible_records::record::{content_line, content_sha256, parse};
use serde_json::Value;

fn file() -> Value {
    let path = format!(
        "{}/tests/vectors/content-lines.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).expect("vectors are JSON")
}

fn cases() -> Vec<Value> {
    file()["cases"].as_array().expect("cases").clone()
}

#[test]
fn refused_vectors() {
    let file = file();
    let refused = file["refused"].as_array().expect("refused");
    assert!(refused.len() >= 5);
    for case in refused {
        let text = case["record_text"].as_str().unwrap();
        assert!(
            parse(text.as_bytes()).is_err(),
            "{} was accepted",
            case["name"]
        );
    }
}

#[test]
fn parse_accepts_every_content_case() {
    for case in cases() {
        let text = serde_json::to_vec(&case["record"]).unwrap();
        assert_eq!(parse(&text).expect("accepted"), case["record"]);
    }
}

#[test]
fn content_line_vectors() {
    let cases = cases();
    assert!(cases.len() >= 7, "expected the spec's seven cases");
    let mut failures = Vec::new();
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let line = String::from_utf8(content_line(&case["record"])).expect("UTF-8");
        if line != case["content_line"].as_str().unwrap() {
            failures.push(format!(
                "{name}: line\n  expected {}\n  got      {line}",
                case["content_line"]
            ));
        }
        if content_sha256(&case["record"]) != case["sha256"].as_str().unwrap() {
            failures.push(format!("{name}: sha256"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[cfg(feature = "validate")]
#[test]
fn validates_with_new_common_defs() {
    use legible_records::validate::Schemas;
    use legible_records::COMMON_V1_ID;
    use serde_json::json;

    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://example.com/schemas/com.example.thing/v1.json",
        "title": "thing",
        "type": "object",
        "properties": {
            "repo": {"$ref": format!("{COMMON_V1_ID}#/$defs/identifier")},
            "policy": {"$ref": format!("{COMMON_V1_ID}#/$defs/externalRef")},
            "who": {"$ref": format!("{COMMON_V1_ID}#/$defs/personMatch")}
        }
    });
    let schemas = Schemas::default();
    let good = json!({
        "repo": {"system": "github", "id": "acme/api"},
        "policy": {"type": "tech.monorail.policy.document", "key": "access-control", "revision": 3},
        "who": {"emails": ["ana@acme.example"]}
    });
    assert_eq!(schemas.validate(&schema, &good).unwrap(), vec![]);
    let bad = json!({"repo": {"system": "GitHub", "id": "acme/api"}});
    assert_eq!(schemas.validate(&schema, &bad).unwrap().len(), 1);
    let empty_id = json!({"repo": {"system": "okta", "id": ""}});
    assert_eq!(schemas.validate(&schema, &empty_id).unwrap().len(), 1);
    let short_name = json!({"policy": {"type": "policy", "key": "access-control"}});
    assert_eq!(schemas.validate(&schema, &short_name).unwrap().len(), 1);
}
