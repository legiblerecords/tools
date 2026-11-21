//! Validating records against their types, offline.
//!
//! Schemas refer to each other by `$id`. A [`Schemas`] set holds every schema
//! a validation may need, `org.legiblerecords.common` version 1 included, and
//! resolves references only from that set: nothing is fetched.

use std::collections::BTreeMap;
use std::fmt;

use jsonschema::{Retrieve, Uri};
use serde_json::Value;

use crate::{COMMON_V1, COMMON_V1_ID};

/// One way a record fails its type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// JSON pointer to the value in the record.
    pub pointer: String,
    pub message: String,
}

/// A problem with the schemas themselves, rather than with a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaError(pub String);

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SchemaError {}

/// The schemas a validation may use, by `$id`.
#[derive(Clone, Debug)]
pub struct Schemas {
    by_id: BTreeMap<String, Value>,
}

impl Default for Schemas {
    fn default() -> Self {
        let common: Value =
            serde_json::from_str(COMMON_V1).expect("the bundled common schema is JSON");
        Schemas {
            by_id: BTreeMap::from([(COMMON_V1_ID.to_owned(), common)]),
        }
    }
}

impl Schemas {
    /// Adds a schema under its `$id`. A schema without one can't be
    /// referred to, so it is refused.
    pub fn add(&mut self, schema: Value) -> Result<(), SchemaError> {
        let id = schema
            .get("$id")
            .and_then(Value::as_str)
            .ok_or_else(|| SchemaError("a schema added to the set needs an $id".to_owned()))?
            .to_owned();
        self.by_id.insert(id, schema);
        Ok(())
    }

    /// The schema with this `$id`, if the set has it.
    pub fn get(&self, id: &str) -> Option<&Value> {
        self.by_id.get(id)
    }

    /// The schema for a record's `$type` and `version`: the one whose
    /// `$type` and `version` consts match.
    pub fn for_record(&self, record: &Value) -> Option<&Value> {
        let kind = record.get("$type")?.as_str()?;
        let version = record.get("version")?.as_u64()?;
        self.by_id.values().find(|schema| {
            let properties = schema.get("properties");
            properties
                .and_then(|p| p.get("$type"))
                .and_then(|t| t.get("const"))
                == Some(&Value::from(kind))
                && properties
                    .and_then(|p| p.get("version"))
                    .and_then(|v| v.get("const"))
                    == Some(&Value::from(version))
        })
    }

    /// Validates `record` against `schema`, resolving references from this
    /// set, and checking formats such as `date` and `email`.
    pub fn validate(&self, schema: &Value, record: &Value) -> Result<Vec<Failure>, SchemaError> {
        let validator = jsonschema::options()
            .should_validate_formats(true)
            .with_retriever(SetRetriever(self.by_id.clone()))
            .build(schema)
            .map_err(|error| SchemaError(format!("the schema doesn't compile: {error}")))?;
        Ok(validator
            .iter_errors(record)
            .map(|error| Failure {
                pointer: error.instance_path().to_string(),
                message: error.to_string(),
            })
            .collect())
    }
}

struct SetRetriever(BTreeMap<String, Value>);

impl Retrieve for SetRetriever {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let key = uri.as_str();
        let key = key.split('#').next().unwrap_or(key);
        self.0.get(key).cloned().ok_or_else(|| {
            Box::new(SchemaError(format!(
                "{key} isn't in the schema set; nothing is fetched"
            ))) as _
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn thing() -> Value {
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://example.org/schemas/org.example.thing/v1.json",
            "type": "object",
            "properties": {
                "$type": {"const": "org.example.thing"},
                "version": {"const": 1},
                "id": {"$ref": format!("{COMMON_V1_ID}#/$defs/slug")},
                "decided_at": {"$ref": format!("{COMMON_V1_ID}#/$defs/date")}
            },
            "required": ["$type", "version", "id"]
        })
    }

    #[test]
    fn a_good_record_passes_and_a_bad_one_fails_with_pointers() {
        let mut schemas = Schemas::default();
        schemas.add(thing()).unwrap();
        let good = json!({"$type": "org.example.thing", "version": 1, "id": "mfa", "decided_at": "2026-11-21"});
        let schema = schemas.for_record(&good).unwrap().clone();
        assert_eq!(schemas.validate(&schema, &good).unwrap(), vec![]);

        let bad = json!({"$type": "org.example.thing", "version": 1, "id": "Not A Slug", "decided_at": "21/11/2026"});
        let pointers: Vec<String> = schemas
            .validate(&schema, &bad)
            .unwrap()
            .into_iter()
            .map(|f| f.pointer)
            .collect();
        assert_eq!(pointers, vec!["/decided_at", "/id"]);
    }

    #[test]
    fn references_outside_the_set_are_not_fetched() {
        let schemas = Schemas::default();
        let schema = json!({"$ref": "https://example.org/elsewhere.json"});
        assert!(schemas.validate(&schema, &json!({})).is_err());
    }
}
