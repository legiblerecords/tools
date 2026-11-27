//! Validating records against their types, offline.
//!
//! Schemas refer to each other by `$id`. A [`Schemas`] set holds every schema
//! a validation may need, `org.legiblerecords.common` version 1 included, and
//! resolves references only from that set: nothing is fetched.
//!
//! Rules (spec/schema-language.md § Checking a record) are reported by rule:
//! each `allOf` member with `x-rule` is left out of the type's own keywords
//! and checked on its own, a standard shape by its keywords and an own shape
//! by [`rules::evaluate`], and a rule that doesn't hold is one failure with
//! the rule's message.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::fmt;

use jsonschema::{Retrieve, Uri, Validator};
use serde_json::{Map, Value};

use crate::rules::{self, Rule};
use crate::short_form::path_kind;
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
    ///
    /// The failures are the type's own, its keywords without the rule
    /// members, then one for each rule that doesn't hold on each object it
    /// sits on, with the rule's message: by the object's pointer in document
    /// order (an object before the ones inside it, members in property name
    /// order, items in index order), then in the order of the rules on one
    /// object. `unique` and `within` fail once for each offending value.
    pub fn validate(&self, schema: &Value, record: &Value) -> Result<Vec<Failure>, SchemaError> {
        let stripped: BTreeMap<String, Value> = self
            .by_id
            .iter()
            .map(|(id, schema)| (id.clone(), without_rules(schema)))
            .collect();
        let validator = jsonschema::options()
            .should_validate_formats(true)
            .with_retriever(SetRetriever(stripped))
            .build(&without_rules(schema))
            .map_err(|error| SchemaError(format!("the schema doesn't compile: {error}")))?;
        let mut failures: Vec<Failure> = validator
            .iter_errors(record)
            .map(|error| Failure {
                pointer: error.instance_path().to_string(),
                message: error.to_string(),
            })
            .collect();
        let mut walk = Walk {
            set: &self.by_id,
            root: schema,
            members: HashMap::new(),
            failures: Vec::new(),
        };
        walk.instance(
            vec![At {
                doc: schema,
                node: schema,
            }],
            record,
            "",
        )?;
        failures.append(&mut walk.failures);
        Ok(failures)
    }
}

/// Whether an `allOf` entry is a rule member: an object with `x-rule`.
fn is_rule_member(entry: &Value) -> bool {
    entry.get("x-rule").is_some()
}

/// `schema` without its rule members: each `allOf` entry with `x-rule`
/// taken out wherever it is, and an `allOf` that empties dropped. Values
/// that are data rather than schemas (`const`, `enum`, `examples`,
/// `default`) are kept as they are.
fn without_rules(schema: &Value) -> Value {
    let Value::Object(map) = schema else {
        return schema.clone();
    };
    let mut out = Map::new();
    for (key, value) in map {
        let value = match (key.as_str(), value) {
            ("const" | "enum" | "examples" | "default", _) => value.clone(),
            ("allOf", Value::Array(entries)) => {
                let kept: Vec<Value> = entries
                    .iter()
                    .filter(|entry| !is_rule_member(entry))
                    .map(without_rules)
                    .collect();
                if kept.is_empty() {
                    continue;
                }
                Value::Array(kept)
            }
            (
                "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas",
                Value::Object(names),
            ) => Value::Object(
                names
                    .iter()
                    .map(|(name, schema)| (name.clone(), without_rules(schema)))
                    .collect(),
            ),
            (_, Value::Array(items)) => Value::Array(items.iter().map(without_rules).collect()),
            (_, other) => without_rules(other),
        };
        out.insert(key.clone(), value);
    }
    Value::Object(out)
}

/// A schema node, with the document it is in, for its local `$ref`s and
/// `$defs`.
#[derive(Clone, Copy)]
struct At<'s> {
    doc: &'s Value,
    node: &'s Value,
}

/// Walks a record and its schema together, checking the rule members of
/// each object's schema.
struct Walk<'s> {
    /// The schemas `$ref`s resolve from, with their rule members.
    set: &'s BTreeMap<String, Value>,
    /// The type's schema, which needn't be in the set.
    root: &'s Value,
    /// Standard shapes' members, compiled, by their address.
    members: HashMap<usize, Validator>,
    failures: Vec<Failure>,
}

impl<'s> Walk<'s> {
    /// Checks the value at `pointer` against the schema nodes that apply to
    /// it, then the values inside it, members in property name order and
    /// items in index order.
    fn instance(
        &mut self,
        nodes: Vec<At<'s>>,
        value: &Value,
        pointer: &str,
    ) -> Result<(), SchemaError> {
        let nodes = self.applying(nodes);
        match value {
            Value::Object(map) => {
                for at in &nodes {
                    self.rules(*at, value, pointer)?;
                }
                let mut names: Vec<&String> = map.keys().collect();
                names.sort();
                for name in names {
                    let inner: Vec<At<'s>> = nodes
                        .iter()
                        .filter_map(|at| {
                            let node = at.node.get("properties")?.get(name.as_str())?;
                            Some(At { doc: at.doc, node })
                        })
                        .collect();
                    if !inner.is_empty() {
                        let step = name.replace('~', "~0").replace('/', "~1");
                        self.instance(inner, &map[name.as_str()], &format!("{pointer}/{step}"))?;
                    }
                }
            }
            Value::Array(items) => {
                let inner: Vec<At<'s>> = nodes
                    .iter()
                    .filter_map(|at| {
                        let node = at.node.get("items").filter(|items| items.is_object())?;
                        Some(At { doc: at.doc, node })
                    })
                    .collect();
                if !inner.is_empty() {
                    for (index, item) in items.iter().enumerate() {
                        self.instance(inner.clone(), item, &format!("{pointer}/{index}"))?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Every node that applies at one value: the given ones, what their
    /// `$ref`s point at, their `allOf` entries other than rule members, and
    /// the other member of an `anyOf` that only adds `null`. Each once.
    fn applying(&self, nodes: Vec<At<'s>>) -> Vec<At<'s>> {
        let mut out: Vec<At<'s>> = Vec::new();
        let mut pending = nodes;
        pending.reverse();
        while let Some(at) = pending.pop() {
            if out.iter().any(|seen| std::ptr::eq(seen.node, at.node)) {
                continue;
            }
            out.push(at);
            let mut next: Vec<At<'s>> = Vec::new();
            if let Some(target) = at.node.get("$ref").and_then(Value::as_str) {
                next.extend(self.resolve(at, target));
            }
            if let Some(Value::Array(entries)) = at.node.get("allOf") {
                next.extend(
                    entries
                        .iter()
                        .filter(|entry| entry.is_object() && !is_rule_member(entry))
                        .map(|node| At { doc: at.doc, node }),
                );
            }
            if let Some(Value::Array(members)) = at.node.get("anyOf") {
                let null = serde_json::json!({"type": "null"});
                let others: Vec<&Value> = members.iter().filter(|m| **m != null).collect();
                if let [only] = others[..] {
                    if members.len() > 1 {
                        next.push(At {
                            doc: at.doc,
                            node: only,
                        });
                    }
                }
            }
            pending.extend(next.into_iter().rev());
        }
        out
    }

    /// The node a `$ref` from `at` points at: a JSON pointer into its own
    /// document, or into a schema of the set, or the type's schema, by
    /// `$id`. `None` for what isn't there, which compiling has refused.
    fn resolve(&self, at: At<'s>, target: &str) -> Option<At<'s>> {
        let (base, fragment) = target.split_once('#').unwrap_or((target, ""));
        let doc = if base.is_empty() {
            at.doc
        } else {
            let id = absolute(base, at.doc.get("$id").and_then(Value::as_str));
            if self.root.get("$id").and_then(Value::as_str) == Some(id.as_str()) {
                self.root
            } else {
                self.set.get(&id)?
            }
        };
        let node = match fragment {
            "" => doc,
            pointer if pointer.starts_with('/') => doc.pointer(pointer)?,
            _ => return None,
        };
        Some(At { doc, node })
    }

    /// Checks the rule members of `at`'s `allOf` on `object`, in order.
    fn rules(&mut self, at: At<'s>, object: &Value, pointer: &str) -> Result<(), SchemaError> {
        let Some(Value::Array(entries)) = at.node.get("allOf") else {
            return Ok(());
        };
        let empty = Map::new();
        let properties = at
            .node
            .get("properties")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        let defs = at
            .doc
            .get("$defs")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        for entry in entries {
            let Some(text) = entry.get("x-rule") else {
                continue;
            };
            let text = text
                .as_str()
                .ok_or_else(|| SchemaError(format!("x-rule {text} isn't a string")))?;
            let rule = rules::parse(text)
                .map_err(|problem| SchemaError(format!("{problem} in `{text}`")))?;
            let messages = if rule.is_standard() {
                if self.holds(entry, text, object)? {
                    Vec::new()
                } else {
                    vec![rules::message(&rule)]
                }
            } else if let Rule::Ascending(list, _) = &rule {
                // A key is a field of the list's items, not of the object.
                rules::evaluate(&rule, object, |key| {
                    path_kind(&format!("{list}[].{key}"), properties, defs)
                })
            } else {
                rules::evaluate(&rule, object, |field| path_kind(field, properties, defs))
            };
            self.failures
                .extend(messages.into_iter().map(|message| Failure {
                    pointer: pointer.to_owned(),
                    message,
                }));
        }
        Ok(())
    }

    /// Whether `object` meets a standard shape's member: its keywords,
    /// without `x-rule`, as a schema of their own.
    fn holds(&mut self, member: &Value, text: &str, object: &Value) -> Result<bool, SchemaError> {
        let validator = match self.members.entry(member as *const Value as usize) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let mut keywords = member.clone();
                if let Value::Object(map) = &mut keywords {
                    map.remove("x-rule");
                }
                let validator = jsonschema::options().build(&keywords).map_err(|error| {
                    SchemaError(format!("the member of `{text}` doesn't compile: {error}"))
                })?;
                entry.insert(validator)
            }
        };
        Ok(validator.is_valid(object))
    }
}

/// A `$ref`'s base, made absolute against the `$id` of the document it is
/// in when it is relative.
fn absolute(base: &str, id: Option<&str>) -> String {
    if base.contains("://") || base.starts_with("urn:") {
        return base.to_owned();
    }
    match id.and_then(|id| id.rfind('/').map(|end| &id[..=end])) {
        Some(directory) => format!("{directory}{base}"),
        None => base.to_owned(),
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

    /// A short form expanded with bare names pointing at common, under the
    /// `$id` `https://example.org/t.json`.
    fn expanded(short: &str) -> Value {
        let options = crate::short_form::Options {
            common: COMMON_V1_ID.to_owned(),
            ..Default::default()
        };
        let mut schema = crate::short_form::expand(short, "t", &options).unwrap();
        schema["$id"] = json!("https://example.org/t.json");
        schema
    }

    fn failures(schemas: &Schemas, schema: &Value, record: &Value) -> Vec<(String, String)> {
        schemas
            .validate(schema, record)
            .unwrap()
            .into_iter()
            .map(|f| (f.pointer, f.message))
            .collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(p, m)| (p.to_string(), m.to_string()))
            .collect()
    }

    #[test]
    fn nested_items_rules_report_each_instance() {
        // Review Focus 2: a rule on a def reached through items is checked
        // on each item, at its own pointer; a rule on the root at "".
        let schema = expanded(
            "fields:\n  experts:\n    items:\n      fields:\n        id: slug\n  \
             statements: t.statement[]\n\
             rules:\n  - within(statements[].estimates[].expert, experts[].id)\n\
             defs:\n  statement:\n    fields:\n      estimates:\n        items:\n          \
             fields:\n            expert: slug\n    rules:\n      - unique(estimates, expert)\n",
        );
        let record = json!({
            "experts": [{"id": "ann"}, {"id": "bob"}],
            "statements": [
                {"estimates": [{"expert": "ann"}, {"expert": "bob"}]},
                {"estimates": [{"expert": "bob"}, {"expert": "bob"}, {"expert": "eve"}]}
            ]
        });
        assert_eq!(
            failures(&Schemas::default(), &schema, &record),
            pairs(&[
                (
                    "",
                    "eve at statements[].estimates[].expert isn't among experts[].id"
                ),
                (
                    "/statements/1",
                    "more than one item in estimates has expert bob"
                ),
            ])
        );
    }

    #[test]
    fn rule_on_non_object_item_is_silent() {
        // Review Focus 5: an item that isn't an object fails the type's own
        // keywords only; no rule on the items reports it.
        let schema = expanded(
            "fields:\n  approvals:\n    items:\n      fields:\n        at?: datetime\n        \
             on?: date\n        starts?: date\n        ends?: date\n      rules:\n        \
             - at_most_one(at, on)\n        - one_of(at, on)\n        - before(starts, ends)\n",
        );
        let got = failures(
            &Schemas::default(),
            &schema,
            &json!({"approvals": ["x", 3, null]}),
        );
        assert_eq!(got.len(), 3, "{got:?}");
        assert!(got.iter().all(|(_, m)| !m.contains("at and on")), "{got:?}");
    }

    #[test]
    fn a_rule_is_reported_once_by_its_message_after_the_types_own() {
        let schema = expanded(
            "fields:\n  at?: datetime\n  on?: date\n  name: string\nrules:\n  - one_of(at, on)\n",
        );
        assert_eq!(
            failures(&Schemas::default(), &schema, &json!({"name": 1})),
            vec![
                ("/name".to_owned(), "1 is not of type \"string\"".to_owned()),
                ("".to_owned(), "needs exactly one of at and on".to_owned()),
            ]
        );
    }

    #[test]
    fn sibling_objects_come_in_property_name_order() {
        let schema = expanded(
            "fields:\n  b:\n    fields:\n      x?: string\n      y?: string\n    rules:\n      \
             - any_of(x, y)\n  a:\n    fields:\n      x?: string\n      y?: string\n    \
             rules:\n      - any_of(x, y)\n      - at_most_one(x, y)\n",
        );
        let record: Value =
            serde_json::from_str(r#"{"b": {}, "a": {"x": "1", "y": "2"}}"#).unwrap();
        assert_eq!(
            failures(&Schemas::default(), &schema, &record),
            pairs(&[("/a", "x and y both given"), ("/b", "needs x or y")])
        );
    }

    #[test]
    fn an_ascending_key_takes_its_kind_from_the_items_not_a_field_of_the_same_name() {
        // The object's own `at` is a number; the items' `at` is a datetime.
        let schema = expanded(
            "fields:\n  at?: number\n  history:\n    items:\n      fields:\n        at: datetime\n\
             rules:\n  - ascending(history, at)\n",
        );
        let schemas = Schemas::default();
        let in_order = json!({"at": 1, "history": [
            {"at": "2026-01-01T10:00:00+02:00"}, {"at": "2026-01-01T09:00:00Z"}]});
        assert_eq!(failures(&schemas, &schema, &in_order), vec![]);
        let out_of_order = json!({"at": 1, "history": [
            {"at": "2026-01-01T09:00:00Z"}, {"at": "2026-01-01T10:00:00+02:00"}]});
        assert_eq!(
            failures(&schemas, &schema, &out_of_order),
            pairs(&[("", "history isn't in order of at")])
        );
    }

    #[test]
    fn person_match_needs_emails_or_identifiers() {
        // The rule sits in common, reached by $ref from the set.
        let schema = expanded("fields:\n  who: personMatch\n");
        let schemas = Schemas::default();
        assert_eq!(
            failures(
                &schemas,
                &schema,
                &json!({"who": {"emails": ["a@example.org"]}})
            ),
            vec![]
        );
        assert_eq!(
            failures(
                &schemas,
                &schema,
                &json!({"who": {"emails": [], "name": "Ann"}})
            ),
            pairs(&[("/who", "needs emails or identifiers")])
        );
    }

    #[test]
    fn rules_in_other_schemas_of_the_set_are_checked() {
        let mut schemas = Schemas::default();
        schemas
            .add(json!({
                "$id": "https://example.org/other.json",
                "$defs": {"window": {
                    "type": "object",
                    "properties": {
                        "from": {"$ref": format!("{COMMON_V1_ID}#/$defs/date")},
                        "to": {"$ref": format!("{COMMON_V1_ID}#/$defs/date")}
                    },
                    "allOf": [{"x-rule": "before(from, to)"}]
                }}
            }))
            .unwrap();
        let schema = json!({
            "$id": "https://example.org/t.json",
            "type": "object",
            "properties": {"w": {"$ref": "https://example.org/other.json#/$defs/window"}}
        });
        assert_eq!(
            failures(
                &schemas,
                &schema,
                &json!({"w": {"from": "2026-02-02", "to": "2026-02-01"}})
            ),
            pairs(&[("/w", "from 2026-02-02 isn't before to 2026-02-01")])
        );
    }

    #[test]
    fn a_rule_through_a_nullable_ref_is_checked() {
        let schema = expanded(
            "fields:\n  w: t.window?\ndefs:\n  window:\n    fields:\n      a?: string\n      \
             b?: string\n    rules:\n      - any_of(a, b)\n",
        );
        let schemas = Schemas::default();
        assert_eq!(failures(&schemas, &schema, &json!({"w": null})), vec![]);
        assert_eq!(
            failures(&schemas, &schema, &json!({"w": {}})),
            pairs(&[("/w", "needs a or b")])
        );
    }

    #[test]
    fn a_rule_member_that_is_not_a_rule_is_a_schema_error() {
        let schema = json!({
            "type": "object",
            "allOf": [{"x-rule": "frob(a, b)"}]
        });
        assert!(Schemas::default().validate(&schema, &json!({})).is_err());
    }

    #[test]
    fn references_outside_the_set_are_not_fetched() {
        let schemas = Schemas::default();
        let schema = json!({"$ref": "https://example.org/elsewhere.json"});
        assert!(schemas.validate(&schema, &json!({})).is_err());
    }
}
