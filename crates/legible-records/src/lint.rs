//! The published subset (spec/rules.md § The published subset): what an
//! expanded published type may not use.

use serde_json::{json, Map, Value};

use crate::short_form::{is_type_identifier, rule_entry, rule_holder, NoMembers};

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

/// The forbidden keywords that a rule member may use.
const RULE_KEYWORDS: [&str; 4] = ["if", "then", "not", "oneOf"];

/// Keywords whose value is a schema.
const SCHEMA_VALUED: [&str; 10] = [
    "items",
    "additionalProperties",
    "contains",
    "propertyNames",
    "unevaluatedItems",
    "unevaluatedProperties",
    "not",
    "if",
    "then",
    "else",
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

const NOT_A_RULE_MEMBER: &str = "allOf entries must be rule members";

/// Checks an expanded schema: that it is a published type, and that it stays
/// within the published subset, each rule member included. An empty list
/// means it passes.
pub fn lint(schema: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(object) = schema.as_object() else {
        findings.push(finding("", "a schema must be an object"));
        return findings;
    };
    if let Some(message) = not_published(object) {
        findings.push(finding("", &message));
    }
    let empty = Map::new();
    let defs = object
        .get("$defs")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let walk = Walk { defs };
    walk.node(schema, "", false, &mut findings);
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

/// The walk over a schema's subschemas.
struct Walk<'a> {
    /// The schema's own `$defs`, which rule paths step through.
    defs: &'a Map<String, Value>,
}

impl Walk<'_> {
    /// Checks `node` and everything under it. `in_member` is set inside a
    /// rule member, where `if`, `then`, `not`, `oneOf`, `anyOf` and `allOf`
    /// are the rule's.
    fn node(&self, node: &Value, pointer: &str, in_member: bool, findings: &mut Vec<Finding>) {
        let Some(object) = node.as_object() else {
            return;
        };
        for keyword in FORBIDDEN {
            if in_member && RULE_KEYWORDS.contains(&keyword) {
                continue;
            }
            if object.contains_key(keyword) {
                findings.push(finding(
                    &child(pointer, keyword),
                    &format!("{keyword} isn't in the published subset"),
                ));
            }
        }
        if let (false, Some(members)) = (in_member, object.get("anyOf").and_then(Value::as_array)) {
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
                self.node(value, &child(pointer, keyword), in_member, findings);
            }
        }
        for keyword in SCHEMA_MAPS {
            if let Some(Value::Object(map)) = object.get(keyword) {
                let here = child(pointer, keyword);
                for (name, value) in map {
                    self.node(value, &child(&here, name), in_member, findings);
                }
            }
        }
        for keyword in SCHEMA_LISTS {
            let here = child(pointer, keyword);
            if keyword == "allOf" && !in_member {
                self.rule_members(object, &here, findings);
            } else if let Some(Value::Array(list)) = object.get(keyword) {
                for (index, value) in list.iter().enumerate() {
                    self.node(value, &format!("{here}/{index}"), in_member, findings);
                }
            }
        }
    }

    /// Checks `object`'s `allOf`, which must hold only rule members, on an
    /// object that can hold them ([`rule_holder`]): each entry is exactly
    /// what [`rule_entry`] gives for its `x-rule` on `object`'s
    /// `properties`, and no two have the same text.
    fn rule_members(&self, object: &Map<String, Value>, here: &str, findings: &mut Vec<Finding>) {
        let none = Map::new();
        let (entries, properties, not_an_object) = match rule_holder(object) {
            Ok((entries, properties)) => (entries, properties, None),
            Err(NoMembers::Absent) => return,
            Err(NoMembers::NotAList) => {
                findings.push(finding(here, NOT_A_RULE_MEMBER));
                return;
            }
            Err(NoMembers::Empty) => {
                findings.push(finding(here, "allOf is empty"));
                return;
            }
            Err(NoMembers::NotAnObject(problem)) => {
                let Some(Value::Array(entries)) = object.get("allOf") else {
                    return;
                };
                (&entries[..], &none, Some(problem))
            }
        };
        let mut texts: Vec<&str> = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let at = format!("{here}/{index}");
            let Some(text) = entry.get("x-rule").and_then(Value::as_str) else {
                findings.push(finding(&at, NOT_A_RULE_MEMBER));
                self.node(entry, &at, false, findings);
                continue;
            };
            let problem = if let Some(problem) = not_an_object {
                Some(format!("rule member {text}: {problem}"))
            } else if texts.contains(&text) {
                Some(format!("rule member {text}: rule written twice"))
            } else {
                match rule_entry(text, properties, self.defs) {
                    Ok(member) if member == *entry => None,
                    Ok(_) => Some(format!("rule member doesn't match its rule {text}")),
                    Err(problem) => Some(format!("rule member {text}: {problem}")),
                }
            };
            if let Some(message) = problem {
                findings.push(finding(&at, &message));
            }
            texts.push(text);
            self.node(entry, &at, true, findings);
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

    /// The body of § Expansion's example, with a member for each standard
    /// shape and one for an own shape.
    fn triage() -> Value {
        let mut schema = published(json!({
            "status": {"type": "string", "examples": ["active", "revoked"]},
            "subjects": {"type": "array", "items": {"type": "string"}},
            "subject_refs": {"type": "array", "items": {"$ref": "#/$defs/externalRef"}},
            "at": {"$ref": "https://legiblerecords.org/schemas/org.legiblerecords.common/v1.json#/$defs/datetime"},
            "on": {"$ref": "https://legiblerecords.org/schemas/org.legiblerecords.common/v1.json#/$defs/date"},
            "revoked_on": {"$ref": "https://legiblerecords.org/schemas/org.legiblerecords.common/v1.json#/$defs/date"},
            "note": {"type": "string"}
        }));
        schema["$defs"] =
            json!({"externalRef": {"type": "object", "properties": {"id": {"type": "string"}}}});
        schema["allOf"] = json!([
            { "x-rule": "one_of(at, on)",
              "oneOf": [ { "required": ["at"] }, { "required": ["on"] } ] },
            { "x-rule": "any_of(subjects, subject_refs)",
              "anyOf": [
                { "required": ["subjects"], "properties": { "subjects": { "minItems": 1 } } },
                { "required": ["subject_refs"], "properties": { "subject_refs": { "minItems": 1 } } } ] },
            { "x-rule": "requires(status = revoked, revoked_on)",
              "if": { "required": ["status"], "properties": { "status": { "const": "revoked" } } },
              "then": { "required": ["revoked_on"] } },
            { "x-rule": "at_most_one(note, subjects)",
              "not": { "allOf": [
                { "required": ["note"], "properties": { "note": { "minLength": 1 } } },
                { "required": ["subjects"], "properties": { "subjects": { "minItems": 1 } } } ] } },
            { "x-rule": "requires(not status in (active), any_of(note, subjects))",
              "if": { "not": { "required": ["status"], "properties": { "status": { "enum": ["active"] } } } },
              "then": { "anyOf": [
                { "required": ["note"], "properties": { "note": { "minLength": 1 } } },
                { "required": ["subjects"], "properties": { "subjects": { "minItems": 1 } } } ] } },
            { "x-rule": "before(on, revoked_on)" }
        ]);
        schema
    }

    fn messages(schema: &Value) -> Vec<(String, String)> {
        lint(schema)
            .into_iter()
            .map(|f| (f.pointer, f.message))
            .collect()
    }

    fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
        expected
            .iter()
            .map(|(p, m)| ((*p).to_owned(), (*m).to_owned()))
            .collect()
    }

    #[test]
    fn rule_members_may_use_oneof_if_then_not_anyof() {
        assert_eq!(messages(&triage()), vec![]);
    }

    /// What expansion writes, on the document, a field, an `items` mapping
    /// and an entry in `defs`, passes.
    #[test]
    fn expanded_rules_pass() {
        let short = "type: org.example.thing\nversion: 1\nfields:\n  a?: string\n  b?: string[]\n  n?: integer\n  m?: integer\n  experts?: thing.expert[]\n  picks?: slug[]\n  m2?:\n    fields:\n      x?: date\n      y?: date\n    rules:\n      - not_after(x, y)\n      - at_most_one(x, y)\n  l?:\n    items:\n      fields:\n        k?: known(p, q)\n        v?: string\n      rules:\n        - requires(k in (p, q), v)\n        - requires(not k = p, any_of(k, v))\nrules:\n  - one_of(a, b)\n  - any_of(a, b, n)\n  - before(n, m)\n  - within(picks[], experts[].id)\n  - unique(l, v)\ndefs:\n  expert:\n    fields:\n      id: slug\n      p?: string\n      q?: string\n    rules:\n      - one_of(p, q)\n";
        let options = crate::short_form::Options::published("https://example.org/schemas/");
        let body = crate::short_form::expand(short, "thing", &options).unwrap();
        assert_eq!(body["allOf"].as_array().unwrap().len(), 5, "{body}");
        assert_eq!(messages(&body), vec![]);
    }

    #[test]
    fn allof_entry_without_x_rule_is_a_finding() {
        let mut schema = triage();
        schema["allOf"]
            .as_array_mut()
            .unwrap()
            .push(json!({"required": ["note"]}));
        assert_eq!(
            messages(&schema),
            pairs(&[("/allOf/6", "allOf entries must be rule members")])
        );
    }

    #[test]
    fn rule_member_keywords_must_match_its_rule() {
        let mut schema = triage();
        schema["allOf"][2]["then"] = json!({"required": ["on"]});
        assert_eq!(
            messages(&schema),
            pairs(&[(
                "/allOf/2",
                "rule member doesn't match its rule requires(status = revoked, revoked_on)"
            )])
        );
    }

    #[test]
    fn oneof_outside_a_rule_member_still_forbidden() {
        let mut schema = triage();
        schema["properties"]["note"]["oneOf"] = json!([{"minLength": 1}, {"maxLength": 0}]);
        schema["allOf"]
            .as_array_mut()
            .unwrap()
            .push(json!({"oneOf": [{"required": ["at"]}, {"required": ["on"]}]}));
        assert_eq!(
            messages(&schema),
            pairs(&[
                (
                    "/properties/note/oneOf",
                    "oneOf isn't in the published subset"
                ),
                ("/allOf/6", "allOf entries must be rule members"),
                ("/allOf/6/oneOf", "oneOf isn't in the published subset"),
            ])
        );
    }

    #[test]
    fn else_inside_a_rule_member_forbidden() {
        let mut schema = triage();
        schema["allOf"][2]["else"] = json!({"required": ["note"]});
        schema["allOf"][2]["then"]["additionalProperties"] = json!(false);
        schema["allOf"][0]["oneOf"][0]["dependentRequired"] = json!({"at": ["on"]});
        schema["allOf"][4]["if"]["not"]["dependentSchemas"] = json!({"at": {}});
        let doesnt_match = |text: &str| format!("rule member doesn't match its rule {text}");
        let expected = [
            ("/allOf/0", doesnt_match("one_of(at, on)")),
            (
                "/allOf/0/oneOf/0/dependentRequired",
                "dependentRequired isn't in the published subset".to_owned(),
            ),
            ("/allOf/2", doesnt_match("requires(status = revoked, revoked_on)")),
            ("/allOf/2/else", "else isn't in the published subset".to_owned()),
            (
                "/allOf/2/then/additionalProperties",
                "additionalProperties: false isn't allowed: readers must accept fields they don't know".to_owned(),
            ),
            (
                "/allOf/4",
                doesnt_match("requires(not status in (active), any_of(note, subjects))"),
            ),
            (
                "/allOf/4/if/not/dependentSchemas",
                "dependentSchemas isn't in the published subset".to_owned(),
            ),
        ];
        let expected: Vec<(String, String)> = expected
            .into_iter()
            .map(|(p, m)| (p.to_owned(), m))
            .collect();
        assert_eq!(messages(&schema), expected);
    }

    /// Lint accepts as a rule member exactly what generation does: a member
    /// whose rule has a problem is a finding that says what it is.
    #[test]
    fn rule_member_problems_say_why() {
        let cases = [
            (
                json!({"x-rule": "one_of(at, nope)",
                       "oneOf": [{"required": ["at"]}, {"required": ["nope"]}]}),
                "rule member one_of(at, nope): no field nope",
            ),
            (
                json!({"x-rule": "one_of(at,  on)",
                       "oneOf": [{"required": ["at"]}, {"required": ["on"]}]}),
                "rule member one_of(at,  on): its text is one_of(at, on)",
            ),
            (
                json!({"x-rule": "one_of(at, maybe)",
                       "oneOf": [{"required": ["at"]}, {"required": ["maybe"]}]}),
                "rule member one_of(at, maybe): maybe is nullable",
            ),
            (
                json!({"x-rule": "before(on, at)"}),
                "rule member before(on, at): before compares a date with a datetime",
            ),
            (
                json!({"x-rule": "before(on, note)"}),
                "rule member before(on, note): before needs numbers, dates or datetimes: note is string",
            ),
            (
                json!({"x-rule": "frob(at, on)"}),
                "rule member frob(at, on): unknown shape frob",
            ),
            (
                json!({"x-rule": "one_of(at, on)",
                       "oneOf": [{"required": ["at"]}, {"required": ["on"]}]}),
                "rule member one_of(at, on): rule written twice",
            ),
            (
                json!({"x-rule": 7}),
                "allOf entries must be rule members",
            ),
        ];
        for (member, message) in cases {
            let mut schema = triage();
            schema["properties"]["maybe"] = json!({"type": ["string", "null"]});
            schema["allOf"].as_array_mut().unwrap().push(member);
            assert_eq!(messages(&schema), pairs(&[("/allOf/6", message)]));
        }
    }

    /// A kind message writes a ref by its definition's name.
    #[test]
    fn kind_messages_name_refs_by_definition() {
        let mut schema = triage();
        schema["properties"]["slug"] = json!({"$ref": "https://legiblerecords.org/schemas/org.legiblerecords.common/v1.json#/$defs/slug"});
        schema["properties"]["refs"] =
            json!({"type": "array", "items": {"$ref": "#/$defs/externalRef"}});
        for (rule, message) in [
            ("before(on, slug)", "rule member before(on, slug): before needs numbers, dates or datetimes: slug is slug"),
            ("not_after(on, refs)", "rule member not_after(on, refs): not_after needs numbers, dates or datetimes: refs is externalRef[]"),
        ] {
            let mut schema = schema.clone();
            schema["allOf"].as_array_mut().unwrap().push(json!({"x-rule": rule}));
            assert_eq!(messages(&schema), pairs(&[("/allOf/6", message)]));
        }
    }

    /// Rule members need an object that can't be null, as generation does.
    #[test]
    fn rule_members_need_an_object_that_cannot_be_null() {
        let dates = json!({
            "a": {"$ref": "https://legiblerecords.org/schemas/org.legiblerecords.common/v1.json#/$defs/date"},
            "b": {"$ref": "https://legiblerecords.org/schemas/org.legiblerecords.common/v1.json#/$defs/date"}
        });
        let cases = [
            (
                json!(["object", "null"]),
                "rule member before(a, b): rules on an object that may be null",
            ),
            (
                json!("string"),
                "rule member before(a, b): rules need an object with fields",
            ),
            (
                Value::Null,
                "rule member before(a, b): rules need an object with fields",
            ),
        ];
        for (kind, message) in cases {
            let mut m = json!({"properties": dates, "allOf": [{"x-rule": "before(a, b)"}]});
            if !kind.is_null() {
                m["type"] = kind;
            }
            let mut schema = triage();
            schema["properties"]["m"] = m;
            assert_eq!(
                messages(&schema),
                pairs(&[("/properties/m/allOf/0", message)])
            );
        }
    }

    #[test]
    fn empty_allof_is_a_finding() {
        let mut schema = triage();
        schema["allOf"] = json!([]);
        assert_eq!(messages(&schema), pairs(&[("/allOf", "allOf is empty")]));
        schema["allOf"] = json!({"x-rule": "one_of(at, on)"});
        assert_eq!(
            messages(&schema),
            pairs(&[("/allOf", "allOf entries must be rule members")])
        );
    }

    /// A member is checked against the object that holds its `allOf`, and
    /// paths step through the schema's own `$defs`.
    #[test]
    fn nested_rule_members_use_their_object() {
        let mut schema = triage();
        schema["properties"]["m"] = json!({
            "type": "object",
            "properties": {"x": {"type": "integer"}, "refs": {"type": "array", "items": {"$ref": "#/$defs/externalRef"}}},
            "allOf": [
                {"x-rule": "within(refs[].id, refs[].id)"},
                {"x-rule": "one_of(x, at)", "oneOf": [{"required": ["x"]}, {"required": ["at"]}]}
            ]
        });
        assert_eq!(
            messages(&schema),
            pairs(&[(
                "/properties/m/allOf/1",
                "rule member one_of(x, at): no field at"
            )])
        );
    }

    #[test]
    fn says_when_a_schema_is_not_published() {
        let findings = lint(&json!({"type": "object"}));
        assert_eq!(findings[0].message, "not a published type: no $type const");
    }
}
