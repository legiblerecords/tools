//! Compatible changes (spec/rules.md § Compatible changes): within a major
//! version, a new schema may only add optional fields, add values to open
//! lists, relax constraints, and change descriptions and examples.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

/// One change that breaks compatibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Break {
    /// JSON pointer to the place in the old schema.
    pub pointer: String,
    pub message: String,
}

/// Compares two expanded schemas, `old` and `new`, and lists every change
/// that a reader of `old` records, or a writer of them, could trip on. An
/// empty list means `new` is a compatible version of `old`.
pub fn check(old: &Value, new: &Value) -> Vec<Break> {
    let mut breaks = Vec::new();
    let (Some(old), Some(new)) = (old.as_object(), new.as_object()) else {
        breaks.push(brk("", "both schemas must be objects"));
        return breaks;
    };
    if old.get("$id") != new.get("$id") {
        breaks.push(brk(
            "/$id",
            "$id changed: a compatible change keeps the type and major version",
        ));
    }
    node(old, new, "", &mut breaks);
    breaks
}

fn node(
    old: &Map<String, Value>,
    new: &Map<String, Value>,
    pointer: &str,
    breaks: &mut Vec<Break>,
) {
    types(old, new, pointer, breaks);
    same(old, new, pointer, "const", breaks);
    same(old, new, pointer, "$ref", breaks);
    same(old, new, pointer, "format", breaks);
    same(old, new, pointer, "pattern", breaks);
    lower_bound(old, new, pointer, "minimum", breaks);
    lower_bound(old, new, pointer, "exclusiveMinimum", breaks);
    lower_bound(old, new, pointer, "minLength", breaks);
    lower_bound(old, new, pointer, "minItems", breaks);
    upper_bound(old, new, pointer, "maximum", breaks);
    upper_bound(old, new, pointer, "exclusiveMaximum", breaks);
    upper_bound(old, new, pointer, "maxLength", breaks);
    upper_bound(old, new, pointer, "maxItems", breaks);
    enums(old, new, pointer, breaks);
    required(old, new, pointer, breaks);
    rules(old, new, pointer, breaks);
    if old.get("additionalProperties") != Some(&Value::Bool(false))
        && new.get("additionalProperties") == Some(&Value::Bool(false))
    {
        breaks.push(brk(
            &child(pointer, "additionalProperties"),
            "additionalProperties became false",
        ));
    }
    for keyword in ["properties", "$defs"] {
        let old_map = old.get(keyword).and_then(Value::as_object);
        let new_map = new.get(keyword).and_then(Value::as_object);
        let Some(old_map) = old_map else { continue };
        let here = child(pointer, keyword);
        for (name, old_child) in old_map {
            let at = child(&here, name);
            match new_map.and_then(|map| map.get(name)) {
                None => breaks.push(brk(&at, &format!("{name} was removed"))),
                Some(new_child) => pair(old_child, new_child, &at, breaks),
            }
        }
    }
    for keyword in ["items", "additionalProperties"] {
        if let (Some(old_child), Some(new_child)) = (old.get(keyword), new.get(keyword)) {
            if old_child.is_object() && new_child.is_object() {
                pair(old_child, new_child, &child(pointer, keyword), breaks);
            }
        }
    }
    if let (Some(Value::Array(old_list)), Some(Value::Array(new_list))) =
        (old.get("anyOf"), new.get("anyOf"))
    {
        if old_list.len() != new_list.len() {
            breaks.push(brk(&child(pointer, "anyOf"), "anyOf changed"));
        } else {
            for (index, (o, n)) in old_list.iter().zip(new_list).enumerate() {
                pair(
                    o,
                    n,
                    &format!("{}/{index}", child(pointer, "anyOf")),
                    breaks,
                );
            }
        }
    }
}

fn pair(old: &Value, new: &Value, pointer: &str, breaks: &mut Vec<Break>) {
    match (old.as_object(), new.as_object()) {
        (Some(old), Some(new)) => node(old, new, pointer, breaks),
        _ if old == new => {}
        _ => breaks.push(brk(pointer, "changed")),
    }
}

fn type_set(node: &Map<String, Value>) -> Option<BTreeSet<String>> {
    match node.get("type")? {
        Value::String(kind) => Some(BTreeSet::from([kind.clone()])),
        Value::Array(kinds) => Some(
            kinds
                .iter()
                .filter_map(|kind| kind.as_str().map(str::to_owned))
                .collect(),
        ),
        _ => None,
    }
}

fn types(
    old: &Map<String, Value>,
    new: &Map<String, Value>,
    pointer: &str,
    breaks: &mut Vec<Break>,
) {
    match (type_set(old), type_set(new)) {
        (Some(old_types), Some(new_types)) => {
            // integer values are still valid where number is allowed.
            let lost: Vec<&String> = old_types
                .iter()
                .filter(|kind| {
                    !new_types.contains(*kind)
                        && !(kind.as_str() == "integer" && new_types.contains("number"))
                })
                .collect();
            if !lost.is_empty() {
                let lost: Vec<&str> = lost.iter().map(|kind| kind.as_str()).collect();
                breaks.push(brk(
                    &child(pointer, "type"),
                    &format!("type no longer allows {}", lost.join(", ")),
                ));
            }
        }
        (None, Some(_)) => breaks.push(brk(&child(pointer, "type"), "type was added")),
        _ => {}
    }
}

fn same(
    old: &Map<String, Value>,
    new: &Map<String, Value>,
    pointer: &str,
    keyword: &str,
    breaks: &mut Vec<Break>,
) {
    match (old.get(keyword), new.get(keyword)) {
        (Some(o), Some(n)) if o != n => {
            breaks.push(brk(&child(pointer, keyword), &format!("{keyword} changed")));
        }
        (None, Some(_)) => {
            breaks.push(brk(
                &child(pointer, keyword),
                &format!("{keyword} was added"),
            ));
        }
        _ => {}
    }
}

fn number(value: Option<&Value>) -> Option<f64> {
    value.and_then(Value::as_f64)
}

fn lower_bound(
    old: &Map<String, Value>,
    new: &Map<String, Value>,
    pointer: &str,
    keyword: &str,
    breaks: &mut Vec<Break>,
) {
    let (o, n) = (number(old.get(keyword)), number(new.get(keyword)));
    let narrowed = match (o, n) {
        (None, Some(_)) => true,
        (Some(o), Some(n)) => n > o,
        _ => false,
    };
    if narrowed {
        breaks.push(brk(
            &child(pointer, keyword),
            &format!("{keyword} was raised"),
        ));
    }
}

fn upper_bound(
    old: &Map<String, Value>,
    new: &Map<String, Value>,
    pointer: &str,
    keyword: &str,
    breaks: &mut Vec<Break>,
) {
    let (o, n) = (number(old.get(keyword)), number(new.get(keyword)));
    let narrowed = match (o, n) {
        (None, Some(_)) => true,
        (Some(o), Some(n)) => n < o,
        _ => false,
    };
    if narrowed {
        breaks.push(brk(
            &child(pointer, keyword),
            &format!("{keyword} was lowered"),
        ));
    }
}

fn enums(
    old: &Map<String, Value>,
    new: &Map<String, Value>,
    pointer: &str,
    breaks: &mut Vec<Break>,
) {
    match (old.get("enum"), new.get("enum")) {
        (Some(Value::Array(o)), Some(Value::Array(n))) => {
            let lost: Vec<String> = o
                .iter()
                .filter(|v| !n.contains(v))
                .map(Value::to_string)
                .collect();
            if !lost.is_empty() {
                breaks.push(brk(
                    &child(pointer, "enum"),
                    &format!("enum lost {}", lost.join(", ")),
                ));
            }
        }
        (None, Some(_)) => {
            let message = if old.contains_key("examples") {
                "an open list became an enum"
            } else {
                "enum was added"
            };
            breaks.push(brk(&child(pointer, "enum"), message));
        }
        _ => {}
    }
}

fn required(
    old: &Map<String, Value>,
    new: &Map<String, Value>,
    pointer: &str,
    breaks: &mut Vec<Break>,
) {
    let names = |node: &Map<String, Value>| -> BTreeSet<String> {
        node.get("required")
            .and_then(Value::as_array)
            .map(|names| {
                names
                    .iter()
                    .filter_map(|name| name.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let (old_names, new_names) = (names(old), names(new));
    for name in new_names.difference(&old_names) {
        breaks.push(brk(
            &child(pointer, "required"),
            &format!("{name} became required"),
        ));
    }
}

/// Rules are compared by their `x-rule` text: one that `new` has and `old`
/// doesn't is added, which breaks; one removed doesn't. The pointer is the
/// object the rules sit on.
fn rules(
    old: &Map<String, Value>,
    new: &Map<String, Value>,
    pointer: &str,
    breaks: &mut Vec<Break>,
) {
    let texts = |node: &Map<String, Value>| -> Vec<String> {
        node.get("allOf")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.get("x-rule")?.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let old_texts = texts(old);
    let mut seen = BTreeSet::new();
    for text in texts(new) {
        if !old_texts.contains(&text) && seen.insert(text.clone()) {
            breaks.push(brk(pointer, &format!("rule added: {text}")));
        }
    }
}

fn child(pointer: &str, key: &str) -> String {
    format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"))
}

fn brk(pointer: &str, message: &str) -> Break {
    Break {
        pointer: pointer.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn base() -> Value {
        json!({
            "$id": "https://example.org/schemas/org.example.thing/v1.json",
            "type": "object",
            "properties": {
                "level": {"type": "string", "examples": ["serious", "existential"]},
                "loss": {"type": "number", "minimum": 0},
                "status": {"type": "string", "enum": ["open", "closed"]},
                "note": {"type": "string"}
            },
            "required": ["level", "loss"]
        })
    }

    fn with(change: impl FnOnce(&mut Value)) -> Value {
        let mut schema = base();
        change(&mut schema);
        schema
    }

    fn messages(new: &Value) -> Vec<String> {
        check(&base(), new).into_iter().map(|b| b.message).collect()
    }

    #[test]
    fn allowed_changes_pass() {
        let new = with(|s| {
            s["properties"]["added"] = json!({"type": "string"});
            s["properties"]["level"]["examples"] = json!(["serious", "existential", "regulatory"]);
            s["properties"]["note"]["type"] = json!(["string", "null"]);
            s["properties"]["note"]["description"] = json!("Anything else.");
            s["properties"]["status"]["enum"] = json!(["open", "closed", "deferred"]);
            s["properties"]["loss"]
                .as_object_mut()
                .unwrap()
                .remove("minimum");
        });
        assert_eq!(messages(&new), Vec::<String>::new());
    }

    #[test]
    fn breaking_changes_are_found() {
        let new = with(|s| {
            s["properties"].as_object_mut().unwrap().remove("note");
            s["required"] = json!(["level", "loss", "status"]);
            s["properties"]["loss"]["minimum"] = json!(1);
            s["properties"]["loss"]["type"] = json!("integer");
            s["properties"]["level"]["enum"] = json!(["serious", "existential"]);
            s["properties"]["status"]["enum"] = json!(["open"]);
        });
        assert_eq!(
            messages(&new),
            vec![
                "status became required",
                "an open list became an enum",
                "type no longer allows number",
                "minimum was raised",
                "note was removed",
                "enum lost \"closed\"",
            ]
        );
    }

    fn rule(text: &str) -> Value {
        json!({"x-rule": text})
    }

    fn with_rules(root: &[&str], status: &[&str]) -> Value {
        with(|s| {
            s["allOf"] = Value::Array(root.iter().map(|text| rule(text)).collect());
            s["properties"]["status"]["allOf"] =
                Value::Array(status.iter().map(|text| rule(text)).collect());
        })
    }

    fn pairs(old: &Value, new: &Value) -> Vec<(String, String)> {
        check(old, new)
            .into_iter()
            .map(|b| (b.pointer, b.message))
            .collect()
    }

    #[test]
    fn added_rule_is_breaking() {
        let old = with_rules(&["any_of(note, status)"], &[]);
        let new = with_rules(
            &["any_of(note, status)", "before(loss, loss)"],
            &["unique(a, b)"],
        );
        assert_eq!(
            pairs(&old, &new),
            vec![
                ("".to_owned(), "rule added: before(loss, loss)".to_owned()),
                (
                    "/properties/status".to_owned(),
                    "rule added: unique(a, b)".to_owned()
                ),
            ]
        );
        assert_eq!(
            pairs(&base(), &with_rules(&["one_of(note, level)"], &[])),
            vec![("".to_owned(), "rule added: one_of(note, level)".to_owned())]
        );
    }

    /// A rule whose text changes is one removed and another added.
    #[test]
    fn changed_rule_text_is_an_added_rule() {
        let old = with_rules(&["one_of(note, level)"], &[]);
        let new = with_rules(&["one_of(level, note)"], &[]);
        assert_eq!(
            pairs(&old, &new),
            vec![("".to_owned(), "rule added: one_of(level, note)".to_owned())]
        );
    }

    #[test]
    fn removed_rule_is_compatible() {
        let old = with_rules(
            &["any_of(note, status)", "before(loss, loss)"],
            &["unique(a, b)"],
        );
        assert_eq!(
            pairs(&old, &with_rules(&["before(loss, loss)"], &[])),
            vec![]
        );
        assert_eq!(pairs(&old, &base()), vec![]);
    }

    #[test]
    fn same_rules_reordered_is_compatible() {
        let old = with_rules(&["any_of(note, status)", "before(loss, loss)"], &[]);
        let new = with_rules(&["before(loss, loss)", "any_of(note, status)"], &[]);
        assert_eq!(pairs(&old, &new), vec![]);
    }

    #[test]
    fn a_new_major_version_is_not_compared_silently() {
        let new =
            with(|s| s["$id"] = json!("https://example.org/schemas/org.example.thing/v2.json"));
        assert_eq!(
            messages(&new),
            vec!["$id changed: a compatible change keeps the type and major version"]
        );
    }
}
