//! Rules in the short form (spec/schema-language.md § Rules): `rules`
//! expanded into `allOf` rule members, the problems that go with them, and
//! `rules` generated back from `allOf`.
//!
//! Everything here is decided from the expanded properties of the object a
//! rule sits on, so expansion, lint and generation agree.

use serde_json::{Map, Value};

use super::{Expander, Generator, Loc};
use crate::rules::{parse, rule_text, Condition, Kind, Rule};

/// How many local `$ref`s a path follows in a row before giving up.
const MAX_REFS: usize = 32;

/// The JSON Schema keywords of one rule's member, given the expanded
/// `properties` of the object it sits on (§ Expansion): `oneOf`, `not`,
/// `anyOf`, or `if` and `then` for a standard shape, and nothing for an own
/// shape. The member also carries the rule's text in `x-rule`, which
/// [`Rule`] doesn't keep; the caller adds it.
///
/// `G(a)` is decided from `a`'s expanded property: `"type": "array"` is a
/// list; `"type": "string"` without `format`, `enum` or `const`, and not a
/// `known(…)` list, is a plain string; anything else gives `required` only.
pub fn rule_member(rule: &Rule, properties: &Map<String, Value>) -> Value {
    let given = |names: &[String]| -> Value {
        Value::Array(names.iter().map(|name| given(name, properties)).collect())
    };
    let mut member = Map::new();
    match rule {
        Rule::OneOf(fields) => {
            member.insert("oneOf".to_owned(), given(fields));
        }
        Rule::AnyOf(fields) => {
            member.insert("anyOf".to_owned(), given(fields));
        }
        Rule::AtMostOne(a, b) => {
            let both = given(&[a.clone(), b.clone()]);
            member.insert("not".to_owned(), object([("allOf", both)]));
        }
        Rule::Requires(when, then) => {
            member.insert("if".to_owned(), condition(when, properties));
            member.insert("then".to_owned(), condition(then, properties));
        }
        Rule::Before(..)
        | Rule::NotAfter(..)
        | Rule::Ascending(..)
        | Rule::Unique(..)
        | Rule::Within(..) => {}
    }
    Value::Object(member)
}

/// What `before`, `not_after` and `ascending` compare a property's values
/// as, read from the expanded property with nothing looked up: `integer`
/// and `number` are numbers, a `$ref` ending `#/$defs/date` is a date, and
/// one ending `#/$defs/datetime` is a moment.
pub fn rule_kind(property: &Value) -> Option<Kind> {
    if let Some(Value::String(kind)) = property.get("type") {
        if kind == "integer" || kind == "number" {
            return Some(Kind::Number);
        }
    }
    let target = property.get("$ref")?.as_str()?;
    if target.ends_with("#/$defs/date") {
        Some(Kind::Date)
    } else if target.ends_with("#/$defs/datetime") {
        Some(Kind::Moment)
    } else {
        None
    }
}

/// The whole rule member: [`rule_member`] with `x-rule` set to `text`.
fn member(text: &str, rule: &Rule, properties: &Map<String, Value>) -> Value {
    let mut member = rule_member(rule, properties);
    if let Value::Object(map) = &mut member {
        map.insert("x-rule".to_owned(), Value::String(text.to_owned()));
    }
    member
}

fn object<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

/// `{"required": [name]}`, with `{"properties": {name: <constraint>}}` when
/// there is one.
fn required(name: &str, constraint: Option<Value>) -> Value {
    let mut out = Map::new();
    out.insert(
        "required".to_owned(),
        Value::Array(vec![Value::String(name.to_owned())]),
    );
    if let Some(constraint) = constraint {
        let properties = Map::from_iter([(name.to_owned(), constraint)]);
        out.insert("properties".to_owned(), Value::Object(properties));
    }
    Value::Object(out)
}

/// `G(a)` (§ Expansion).
fn given(name: &str, properties: &Map<String, Value>) -> Value {
    let constraint = match properties.get(name) {
        Some(property) if is_list(property) => Some(object([("minItems", Value::from(1))])),
        Some(property) if is_plain_string(property) => {
            Some(object([("minLength", Value::from(1))]))
        }
        _ => None,
    };
    required(name, constraint)
}

/// `C(condition)` (§ Expansion).
fn condition(condition: &Condition, properties: &Map<String, Value>) -> Value {
    match condition {
        Condition::Given(name) => given(name, properties),
        Condition::Equals(name, value) => required(name, Some(object([("const", value.clone())]))),
        Condition::In(name, values) => {
            required(name, Some(object([("enum", Value::Array(values.clone()))])))
        }
        Condition::Not(inner) => object([("not", self::condition(inner, properties))]),
        Condition::AnyOf(names) => object([(
            "anyOf",
            Value::Array(names.iter().map(|name| given(name, properties)).collect()),
        )]),
    }
}

fn is_list(property: &Value) -> bool {
    property.get("type").and_then(Value::as_str) == Some("array")
}

fn is_plain_string(property: &Value) -> bool {
    let Some(node) = property.as_object() else {
        return false;
    };
    node.get("type").and_then(Value::as_str) == Some("string")
        && !["format", "enum", "const"]
            .iter()
            .any(|key| node.contains_key(*key))
        && super::known_text(&bare(node), node.get("examples")).is_none()
}

/// A property without the keys that don't change its type:
/// `description`, `examples` and `x-data`.
fn bare(node: &Map<String, Value>) -> Map<String, Value> {
    let mut bare = node.clone();
    for key in ["description", "examples", "x-data"] {
        bare.remove(key);
    }
    bare
}

fn is_nullable(property: &Value) -> bool {
    match property.get("type") {
        Some(Value::String(kind)) if kind == "null" => return true,
        Some(Value::Array(kinds)) if kinds.iter().any(|kind| kind == "null") => return true,
        _ => {}
    }
    if let Some(Value::Array(values)) = property.get("enum") {
        if values.contains(&Value::Null) {
            return true;
        }
    }
    if property.get("const") == Some(&Value::Null) {
        return true;
    }
    match property.get("anyOf") {
        Some(Value::Array(members)) => members.iter().any(is_nullable),
        _ => false,
    }
}

/// Follows local `#/$defs/<name>` refs to the definition they name.
fn deref<'v>(mut node: &'v Value, defs: &'v Map<String, Value>) -> &'v Value {
    for _ in 0..MAX_REFS {
        let Some(name) = node
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(|target| target.strip_prefix("#/$defs/"))
        else {
            break;
        };
        match defs.get(name) {
            Some(def) => node = def,
            None => break,
        }
    }
    node
}

/// Why a path doesn't resolve.
enum Miss<'p> {
    /// `no field <name>`.
    NoField(&'p str),
    /// A `[]` step on a field that isn't a list.
    NotList(&'p str),
}

/// Each step of `path` with its property, stepping into objects through
/// `properties`, into a list's items at `[]`, and through local refs.
fn resolve<'p, 'v>(
    path: &'p str,
    properties: &'v Map<String, Value>,
    defs: &'v Map<String, Value>,
) -> Result<Vec<(&'p str, &'v Value)>, Miss<'p>> {
    let steps: Vec<(&str, bool)> = path
        .split('.')
        .map(|step| match step.strip_suffix("[]") {
            Some(name) => (name, true),
            None => (step, false),
        })
        .collect();
    let mut properties = properties;
    let mut out = Vec::new();
    for (index, &(name, list)) in steps.iter().enumerate() {
        let property = properties.get(name).ok_or(Miss::NoField(name))?;
        out.push((name, property));
        let mut target = deref(property, defs);
        if list {
            if !is_list(target) {
                return Err(Miss::NotList(name));
            }
            target = target
                .get("items")
                .map_or(target, |items| deref(items, defs));
        }
        let Some(&(next, _)) = steps.get(index + 1) else {
            break;
        };
        properties = target
            .get("properties")
            .and_then(Value::as_object)
            .ok_or(Miss::NoField(next))?;
    }
    Ok(out)
}

/// Checks a parsed rule against the expanded `properties` of its object,
/// in the order of § Problems with rules: fields that don't exist, nullable
/// fields, kinds, then lists. The error is the message without
/// `` in `<rule>` ``. `rule written twice` is the caller's, since it needs
/// the other rules.
fn check<'r>(
    rule: &'r Rule,
    properties: &Map<String, Value>,
    defs: &Map<String, Value>,
    describe: impl Fn(&Value) -> String,
) -> Result<(), String> {
    // `ascending(list, key)` and `unique(list, key)` resolve as `list[].key`.
    let paths: Vec<String> = match rule {
        Rule::Ascending(list, key) | Rule::Unique(list, key) => vec![format!("{list}[].{key}")],
        Rule::Within(a, b) => vec![a.clone(), b.clone()],
        _ => rule.fields().into_iter().map(str::to_owned).collect(),
    };
    let resolved: Vec<_> = paths
        .iter()
        .map(|path| resolve(path, properties, defs))
        .collect();
    for result in &resolved {
        if let Err(Miss::NoField(name)) = result {
            return Err(format!("no field {name}"));
        }
    }
    for steps in resolved.iter().flatten() {
        if let Some((name, _)) = steps.iter().find(|(_, property)| is_nullable(property)) {
            return Err(format!("{name} is nullable"));
        }
    }
    let compared: Option<(&str, Vec<(&str, &Value)>)> = match rule {
        Rule::Before(a, b) | Rule::NotAfter(a, b) => {
            let shape = if matches!(rule, Rule::Before(..)) {
                "before"
            } else {
                "not_after"
            };
            let side = |name: &'r str| properties.get(name).map(|property| (name, property));
            side(a).zip(side(b)).map(|(a, b)| (shape, vec![a, b]))
        }
        Rule::Ascending(_, key) => match &resolved[0] {
            Ok(steps) => steps
                .last()
                .map(|(_, property)| ("ascending", vec![(key.as_str(), *property)])),
            Err(_) => None,
        },
        _ => None,
    };
    if let Some((shape, sides)) = compared {
        let mut kinds = Vec::new();
        for (name, property) in sides {
            let kind = rule_kind(property).ok_or_else(|| {
                format!(
                    "{shape} needs numbers, dates or datetimes: {name} is {}",
                    describe(property)
                )
            })?;
            kinds.push(kind);
        }
        if let [a, b] = kinds[..] {
            if a != b {
                return Err(format!(
                    "{shape} compares {} with {}",
                    kind_name(a),
                    kind_name(b)
                ));
            }
        }
    }
    for result in &resolved {
        if let Err(Miss::NotList(name)) = result {
            return Err(format!("{name} isn't a list"));
        }
    }
    Ok(())
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Number => "a number",
        Kind::Date => "a date",
        Kind::Moment => "a datetime",
    }
}

impl Expander<'_> {
    /// Expands the `rules` of a mapping that has them (the document, a
    /// field mapping, an `items` mapping or an entry in `defs`) into
    /// `allOf` on `node`, whose `properties` are already expanded. Reports
    /// each problem with `rules` and with each rule.
    pub(super) fn rules(
        &mut self,
        mapping: &Map<String, Value>,
        loc: &Loc,
        nullable: bool,
        node: &mut Map<String, Value>,
    ) {
        let Some(rules) = mapping.get("rules") else {
            return;
        };
        let loc = loc.key("rules");
        if !mapping.contains_key("fields") {
            self.problem(&loc, "rules without fields");
            return;
        }
        if nullable {
            self.problem(&loc, "rules on an object that may be null");
            return;
        }
        let Some(rules) = rules.as_array() else {
            self.problem(&loc, "must be a list of rules");
            return;
        };
        let empty = Map::new();
        let properties = node
            .get("properties")
            .and_then(Value::as_object)
            .unwrap_or(&empty)
            .clone();
        let mut texts: Vec<String> = Vec::new();
        let mut members = Vec::new();
        for (index, source) in rules.iter().enumerate() {
            let rule_loc = loc.index(index);
            let Some(source) = source.as_str() else {
                self.problem(&rule_loc, "a rule must be a string");
                continue;
            };
            let text = rule_text(source);
            let checked = parse(source).and_then(|rule| {
                check(&rule, &properties, &self.defs, |p| self.describe(p))?;
                if texts.contains(&text) {
                    return Err("rule written twice".to_owned());
                }
                Ok(rule)
            });
            match checked {
                Ok(rule) => members.push(member(&text, &rule, &properties)),
                Err(message) => self.problem(&rule_loc, format!("{message} in `{source}`")),
            }
            texts.push(text);
        }
        if !members.is_empty() {
            node.insert("allOf".to_owned(), Value::Array(members));
        }
    }

    /// A property's type, for a problem's message: its type expression
    /// where it has one.
    fn describe(&self, property: &Value) -> String {
        let generator = Generator {
            own: self.own,
            options: self.options,
            published: self.published,
            defs: &self.defs,
        };
        generator.describe(property)
    }
}

impl Generator<'_> {
    /// The `rules` that give back `all_of` on an object with these
    /// `properties`: each entry's `x-rule`, when every entry is exactly the
    /// member its `x-rule` expands to (`x-rule` included) and every rule
    /// passes its checks. Otherwise `None`, and `allOf` stays under `json`.
    pub(super) fn rules_of(
        &self,
        all_of: &Value,
        properties: &Map<String, Value>,
    ) -> Option<Vec<Value>> {
        let entries = all_of.as_array().filter(|entries| !entries.is_empty())?;
        let mut texts: Vec<&str> = Vec::new();
        for entry in entries {
            let text = entry.get("x-rule")?.as_str()?;
            if rule_text(text) != text || texts.contains(&text) {
                return None;
            }
            let rule = parse(text).ok()?;
            check(&rule, properties, self.defs, |p| self.describe(p)).ok()?;
            if member(text, &rule, properties) != *entry {
                return None;
            }
            texts.push(text);
        }
        Some(
            texts
                .into_iter()
                .map(|text| Value::String(text.to_owned()))
                .collect(),
        )
    }

    fn describe(&self, property: &Value) -> String {
        let Some(node) = property.as_object() else {
            return property.to_string();
        };
        let bare = bare(node);
        if let Some(text) = super::known_text(&bare, node.get("examples")) {
            return text;
        }
        if let Some(text) = self.expr(&bare) {
            return text.text;
        }
        match bare.get("type") {
            Some(Value::String(kind)) => kind.clone(),
            _ => property.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::short_form::{expand, generate, normalize, Options};

    fn problems(short: &str) -> Vec<String> {
        match expand(short, "t", &Options::default()) {
            Ok(body) => panic!("expected problems, got {body}"),
            Err(problems) => problems.iter().map(ToString::to_string).collect(),
        }
    }

    /// Review Focus 4: an `allOf` whose entry has `x-rule` but whose
    /// keywords differ from what the rule expands to goes whole under
    /// `json`, and expands back to itself.
    #[test]
    fn allof_with_x_rule_but_other_keywords_stays_json() {
        let options = Options::default();
        let members = [
            // Not the keywords `one_of(a, b)` expands to.
            json!({"x-rule": "one_of(a, b)", "anyOf": [{"required": ["a"]}, {"required": ["b"]}]}),
            // The right keywords, and one more.
            json!({"x-rule": "one_of(a, b)", "description": "Exactly one.",
                   "oneOf": [{"required": ["a"]}, {"required": ["b"]}]}),
            // The right keywords, but text that isn't the rule's text.
            json!({"x-rule": "one_of(a,  b)", "oneOf": [{"required": ["a"]}, {"required": ["b"]}]}),
            // The right keywords for a rule that names no field here.
            json!({"x-rule": "one_of(a, c)", "oneOf": [{"required": ["a"]}, {"required": ["c"]}]}),
        ];
        for member in members {
            let object = json!({
                "type": "object",
                "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
                "allOf": [member],
            });
            for body in [
                object.clone(),
                json!({"type": "object", "properties": {"m": object}}),
            ] {
                let short = generate(&body, "t", &options).unwrap();
                assert!(!short.contains("rules:"), "{short}");
                assert!(short.contains("allOf:"), "{short}");
                let back = expand(&short, "t", &options).unwrap();
                assert_eq!(normalize(&back), normalize(&body), "{short}");
            }
        }
    }

    #[test]
    fn rules_on_a_field_generate_back() {
        let short = "fields:\n  m:\n    fields:\n      a?: string\n      b?: string[]\n    rules:\n      - one_of(a, b)\n";
        let options = Options::default();
        let body = expand(short, "t", &options).unwrap();
        assert_eq!(generate(&body, "t", &options).unwrap(), short);
    }

    #[test]
    fn within_steps_through_local_refs() {
        let short = "fields:\n  experts: t.expert[]\n  picks: slug[]\n  statements: t.statement[]\nrules:\n  - within(statements[].expert, experts[].id)\n  - within(picks[], experts[].id)\ndefs:\n  expert:\n    fields:\n      id: slug\n  statement:\n    fields:\n      expert: slug\n";
        let options = Options::default();
        let body = expand(short, "t", &options).unwrap();
        assert_eq!(body["allOf"].as_array().unwrap().len(), 2);
        assert_eq!(generate(&body, "t", &options).unwrap(), short);
        assert_eq!(
            problems(&short.replace("statements[].expert,", "statements[].nobody,")),
            ["6: rules[0]: no field nobody in `within(statements[].nobody, experts[].id)`"]
        );
    }

    #[test]
    fn list_and_key_problems() {
        let fields = "fields:\n  n?: integer\n  history?:\n    items:\n      fields:\n        since: datetime\n        note?: string\n        at:\n          fields:\n            on: date\nrules:\n";
        let cases = [
            ("ascending(history, since)", None),
            ("ascending(history, at.on)", None),
            (
                "ascending(history, note)",
                Some("ascending needs numbers, dates or datetimes: note is string"),
            ),
            ("ascending(history, nope)", Some("no field nope")),
            ("ascending(history, at.nope)", Some("no field nope")),
            ("unique(n, since)", Some("n isn't a list")),
            ("within(n[], history[].since)", Some("n isn't a list")),
            ("within(history.since, n)", Some("no field since")),
            ("before(n, n)", None),
            (
                "not_after(n, history)",
                Some("not_after needs numbers, dates or datetimes: history is array"),
            ),
        ];
        for (rule, expected) in cases {
            let short = format!("{fields}  - {rule}\n");
            match (expand(&short, "t", &Options::default()), expected) {
                (Ok(_), None) => {}
                (Err(problems), Some(message)) => assert_eq!(
                    problems
                        .iter()
                        .map(|p| p.message.clone())
                        .collect::<Vec<_>>(),
                    [format!("{message} in `{rule}`")]
                ),
                (got, _) => panic!("{rule}: {got:?}"),
            }
        }
    }

    #[test]
    fn rules_problems_on_mappings() {
        assert_eq!(
            problems("fields:\n  l:\n    items: string\n    rules:\n      - one_of(a, b)\n"),
            ["4: fields.l.rules: rules without fields"]
        );
        assert_eq!(
            problems("fields:\n  a?: string\nrules: one_of(a, b)\n"),
            ["3: rules: must be a list of rules"]
        );
        assert_eq!(
            problems("fields:\n  a?: string\n  b?: string\nrules:\n  - [a]\n"),
            ["5: rules[0]: a rule must be a string"]
        );
    }
}
