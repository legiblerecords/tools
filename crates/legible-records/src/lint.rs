//! The published subset (spec/rules.md § The published subset): what an
//! expanded published type may not use.

use serde_json::{json, Map, Value};

use crate::short_form::is_type_identifier;

/// One place a schema leaves the published subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// JSON pointer to the keyword in the schema, `""` for the schema itself.
    pub pointer: String,
    pub message: String,
}

const FORBIDDEN: [&str; 7] = [
    "if",
    "then",
    "else",
    "not",
    "dependentSchemas",
    "dependentRequired",
    "oneOf",
];

/// Keywords whose value is a schema.
const SCHEMA_VALUED: [&str; 7] = [
    "items",
    "additionalProperties",
    "contains",
    "propertyNames",
    "unevaluatedItems",
    "unevaluatedProperties",
    "not",
];

/// Keywords whose value is a map of schemas.
const SCHEMA_MAPS: [&str; 4] = [
    "properties",
    "$defs",
    "patternProperties",
    "dependentSchemas",
];

/// Keywords whose value is a list of schemas.
const SCHEMA_LISTS: [&str; 4] = ["anyOf", "allOf", "oneOf", "prefixItems"];

/// Checks an expanded schema: that it is a published type, and that it stays
/// within the published subset. An empty list means it passes.
pub fn lint(schema: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(object) = schema.as_object() else {
        findings.push(finding("", "a schema must be an object"));
        return findings;
    };
    if let Some(message) = not_published(object) {
        findings.push(finding("", &message));
    }
    walk(schema, "", &mut findings);
    findings
}

fn not_published(schema: &Map<String, Value>) -> Option<String> {
    let kind = schema
        .get("properties")
        .and_then(|p| p.get("$type"))
        .and_then(|t| t.get("const"))
        .and_then(Value::as_str);
    let Some(kind) = kind else {
        return Some("not a published type: no $type const".to_owned());
    };
    if !is_type_identifier(kind) {
        return Some(format!("not a published type: bad type identifier {kind}"));
    }
    let version = schema
        .get("properties")
        .and_then(|p| p.get("version"))
        .and_then(|v| v.get("const"))
        .and_then(Value::as_u64)
        .filter(|v| *v >= 1);
    let Some(version) = version else {
        return Some("not a published type: no version const of 1 or more".to_owned());
    };
    match schema.get("$id").and_then(Value::as_str) {
        Some(id) if id.ends_with(&format!("{kind}/v{version}.json")) => None,
        Some(id) => Some(format!("$id {id} should end with {kind}/v{version}.json")),
        None => Some("not a published type: no $id".to_owned()),
    }
}

fn walk(node: &Value, pointer: &str, findings: &mut Vec<Finding>) {
    let Some(object) = node.as_object() else {
        return;
    };
    for keyword in FORBIDDEN {
        if object.contains_key(keyword) {
            findings.push(finding(
                &child(pointer, keyword),
                &format!("{keyword} isn't in the published subset"),
            ));
        }
    }
    if let Some(members) = object.get("anyOf").and_then(Value::as_array) {
        let null = json!({"type": "null"});
        if !(members.len() == 2 && members.contains(&null)) {
            findings.push(finding(
                &child(pointer, "anyOf"),
                "anyOf is only for a value that may be null",
            ));
        }
    }
    if object.get("additionalProperties") == Some(&Value::Bool(false)) {
        findings.push(finding(
            &child(pointer, "additionalProperties"),
            "additionalProperties: false isn't allowed: readers must accept fields they don't know",
        ));
    }
    for keyword in SCHEMA_VALUED {
        if let Some(value) = object.get(keyword) {
            walk(value, &child(pointer, keyword), findings);
        }
    }
    for keyword in SCHEMA_MAPS {
        if let Some(Value::Object(map)) = object.get(keyword) {
            let here = child(pointer, keyword);
            for (name, value) in map {
                walk(value, &child(&here, name), findings);
            }
        }
    }
    for keyword in SCHEMA_LISTS {
        if let Some(Value::Array(list)) = object.get(keyword) {
            let here = child(pointer, keyword);
            for (index, value) in list.iter().enumerate() {
                walk(value, &format!("{here}/{index}"), findings);
            }
        }
    }
}

fn child(pointer: &str, key: &str) -> String {
    format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"))
}

fn finding(pointer: &str, message: &str) -> Finding {
    Finding {
        pointer: pointer.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published(extra: Value) -> Value {
        let mut schema = json!({
            "$id": "https://example.org/schemas/org.example.thing/v1.json",
            "type": "object",
            "properties": {
                "$type": {"const": "org.example.thing"},
                "version": {"const": 1}
            },
            "required": ["$type", "version"]
        });
        if let (Some(target), Value::Object(extra)) = (schema["properties"].as_object_mut(), extra)
        {
            target.extend(extra);
        }
        schema
    }

    #[test]
    fn a_plain_published_type_passes() {
        let schema =
            published(json!({"note": {"anyOf": [{"$ref": "#/$defs/x"}, {"type": "null"}]}}));
        assert_eq!(lint(&schema), vec![]);
    }

    #[test]
    fn finds_forbidden_keywords_anywhere() {
        let schema = published(json!({
            "a": {"oneOf": [{"type": "string"}, {"type": "integer"}]},
            "b": {"type": "object", "additionalProperties": false},
            "c": {"anyOf": [{"type": "string"}, {"type": "integer"}]}
        }));
        let pointers: Vec<String> = lint(&schema).into_iter().map(|f| f.pointer).collect();
        assert_eq!(
            pointers,
            vec![
                "/properties/a/oneOf",
                "/properties/b/additionalProperties",
                "/properties/c/anyOf"
            ]
        );
    }

    #[test]
    fn says_when_a_schema_is_not_published() {
        let findings = lint(&json!({"type": "object"}));
        assert_eq!(findings[0].message, "not a published type: no $type const");
    }
}
