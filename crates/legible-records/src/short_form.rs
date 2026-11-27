//! The schema language (spec/schema-language.md): short-form schemas in
//! restricted YAML that expand to JSON Schema 2020-12, and the canonical
//! short form generated back from a schema.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

use serde_json::{json, Map, Number, Value};

use crate::yaml::{emit_string, is_json_number, parse_restricted_with_lines};

mod rules;

#[cfg(feature = "validate")]
pub(crate) use rules::path_kind;
pub(crate) use rules::{rule_entry, rule_holder, NoMembers};
pub use rules::{rule_kind, rule_member};

pub const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";
const PRIMITIVES: [&str; 6] = ["string", "integer", "number", "boolean", "object", "null"];
const RESERVED: [&str; 9] = [
    "string", "integer", "number", "boolean", "object", "null", "ref", "enum", "known",
];
const DOC_KEYS: [&str; 9] = [
    "type",
    "version",
    "title",
    "description",
    "fields",
    "rules",
    "defs",
    "examples",
    "json",
];
/// Properties a published type sets itself.
const PUBLISHED_PROPERTIES: [&str; 2] = ["$type", "version"];

/// Where names in a short-form schema point, and the base of a published
/// type's `$id` (spec/schema-language.md § Expansion).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// Where bare names such as `date` point: `<common>#/$defs/<name>`.
    pub common: String,
    /// Where `<schema>.<name>` points, with `{name}` standing for the schema.
    pub location: String,
    /// The base URL of a published type's `$id`.
    pub base: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            common: "common.schema.json".to_owned(),
            location: "{name}.schema.json".to_owned(),
            base: None,
        }
    }
}

impl Options {
    /// Options for a Legible Records type published under `base`, with
    /// shared names pointing at `org.legiblerecords.common` version 1.
    pub fn published(base: &str) -> Self {
        Options {
            common: crate::COMMON_V1_ID.to_owned(),
            location: "{name}.schema.json".to_owned(),
            base: Some(base.to_owned()),
        }
    }

    fn location_of(&self, schema: &str) -> String {
        if schema == "common" {
            self.common.clone()
        } else {
            self.location.replace("{name}", schema)
        }
    }

    fn schema_at(&self, location: &str) -> Option<String> {
        if location == self.common {
            return Some("common".to_owned());
        }
        let (prefix, suffix) = self.location.split_once("{name}")?;
        let name = location.strip_prefix(prefix)?.strip_suffix(suffix)?;
        (!name.is_empty()).then(|| name.to_owned())
    }
}

/// True for a type identifier: two or more `[a-z0-9-]+` segments joined by `.`.
pub fn is_type_identifier(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() >= 2
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        })
}
const FIELD_KEYS: [&str; 7] = [
    "description",
    "type",
    "fields",
    "rules",
    "items",
    "examples",
    "json",
];
const MAX_DEPTH: usize = 32;

/// One problem in a short-form file: its line, the path in the short form
/// (`fields.owner`) and a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub line: usize,
    pub path: String,
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}: {}", self.line, self.message)
        } else {
            write!(f, "{}: {}: {}", self.line, self.path, self.message)
        }
    }
}

/// Expands short-form text for the schema `name` (`vendor` for
/// `vendor.schema.json`). Reports every problem in the file.
pub fn expand(text: &str, name: &str, options: &Options) -> Result<Value, Vec<Problem>> {
    let (doc, lines) = parse_restricted_with_lines(text).map_err(|error| {
        vec![Problem {
            line: error.line,
            path: String::new(),
            message: error.message,
        }]
    })?;
    let mut expander = Expander::new(name, Some(&lines), options);
    let body = expander.document(&doc);
    if expander.problems.is_empty() {
        Ok(body)
    } else {
        Err(expander.problems)
    }
}

/// The JSON that expanding [`generate`]'s output gives back: `required`
/// lists sorted, `additionalProperties: true` left out, and `$schema` set
/// when missing. Applies to the schema itself, `properties`, `items`,
/// `$defs` and `anyOf` members; other keywords are kept as they are.
pub fn normalize(body: &Value) -> Value {
    let mut body = normalize_node(body);
    if let Some(object) = body.as_object_mut() {
        object
            .entry("$schema")
            .or_insert_with(|| Value::String(DRAFT.to_owned()));
    }
    body
}

/// Generates the canonical short form of a schema body.
pub fn generate(body: &Value, name: &str, options: &Options) -> Result<String, String> {
    let body = normalize(body);
    let Some(object) = body.as_object() else {
        return Err("a schema body must be an object".to_owned());
    };
    let published = published_parts(object, options).is_some();
    // A published type refers to its own definitions by its title.
    let own = match object.get("title").and_then(Value::as_str) {
        Some(title) if published && is_schema_name(title) => title,
        _ => name,
    };
    let empty = Map::new();
    let defs = object
        .get("$defs")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let generator = Generator {
        own,
        options,
        published,
        defs,
    };
    let doc = generator.document(object);
    Ok(emit_document(&doc))
}

// ---------- Expansion ----------

struct Expander<'a> {
    own: &'a str,
    /// A published type's title, which also names the schema itself.
    title: Option<String>,
    root: Loc,
    lines: Option<&'a BTreeMap<String, usize>>,
    options: &'a Options,
    published: bool,
    /// The schema's `$defs`, expanded, for rule paths that step through a
    /// local ref.
    defs: Cow<'a, Map<String, Value>>,
    problems: Vec<Problem>,
}

#[derive(Clone)]
struct Loc {
    pointer: String,
    path: String,
}

impl Loc {
    fn root() -> Self {
        Loc {
            pointer: String::new(),
            path: String::new(),
        }
    }

    fn key(&self, key: &str) -> Self {
        let escaped = key.replace('~', "~0").replace('/', "~1");
        Loc {
            pointer: format!("{}/{escaped}", self.pointer),
            path: if self.path.is_empty() {
                key.to_owned()
            } else {
                format!("{}.{key}", self.path)
            },
        }
    }

    fn index(&self, index: usize) -> Self {
        Loc {
            pointer: format!("{}/{index}", self.pointer),
            path: format!("{}[{index}]", self.path),
        }
    }
}

impl<'a> Expander<'a> {
    fn new(own: &'a str, lines: Option<&'a BTreeMap<String, usize>>, options: &'a Options) -> Self {
        Expander {
            own,
            title: None,
            root: Loc::root(),
            lines,
            options,
            published: false,
            defs: Cow::Owned(Map::new()),
            problems: Vec::new(),
        }
    }

    fn problem(&mut self, loc: &Loc, message: impl Into<String>) {
        let mut pointer = loc.pointer.as_str();
        let line = loop {
            if let Some(line) = self.lines.and_then(|lines| lines.get(pointer)) {
                break *line;
            }
            match pointer.rfind('/') {
                Some(cut) => pointer = &pointer[..cut],
                None => break 1,
            }
        };
        self.problems.push(Problem {
            line,
            path: loc.path.clone(),
            message: message.into(),
        });
    }

    fn document(&mut self, doc: &Value) -> Value {
        let root = self.root.clone();
        let Some(doc) = doc.as_object() else {
            self.problem(&root, "a short-form schema must be a mapping");
            return Value::Null;
        };
        let mut node = Map::new();
        for key in doc.keys() {
            if !DOC_KEYS.contains(&key.as_str()) {
                self.problem(&root.key(key), format!("unknown key {key}"));
            }
        }
        let published = self.published_type(doc, &root);
        self.published = doc.contains_key("type");
        if self.published {
            self.title = doc
                .get("title")
                .and_then(Value::as_str)
                .filter(|title| is_schema_name(title))
                .map(str::to_owned);
        }
        for key in ["title", "description"] {
            if let Some(value) = doc.get(key) {
                if value.is_string() {
                    node.insert(key.to_owned(), value.clone());
                } else {
                    self.problem(&root.key(key), "must be a string");
                }
            }
        }
        if let Some(Value::Object(defs)) = doc.get("defs") {
            // Rule paths may step through local refs, before `defs` are
            // expanded below: expand them once here, for looking up only.
            let mut lookup = Expander::new(self.own, None, self.options);
            lookup.title = self.title.clone();
            lookup.published = self.published;
            let defs = defs
                .iter()
                .map(|(name, value)| (name.clone(), lookup.field_value(value, &root, 0)))
                .collect();
            self.defs = Cow::Owned(defs);
        }
        if let Some(fields) = doc.get("fields") {
            self.object_of(fields, &root.key("fields"), 0, &mut node);
        }
        // Before the published type's own properties, which no rule names.
        self.rules(doc, &root, false, &mut node);
        if let Some((kind, version, id)) = published {
            node.insert("$id".to_owned(), json!(id));
            node.insert("type".to_owned(), json!("object"));
            let properties = node
                .entry("properties")
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(properties) = properties {
                properties.insert("$type".to_owned(), json!({"const": kind}));
                properties.insert("version".to_owned(), json!({"const": version}));
            }
            let mut required = vec![json!("$type"), json!("version")];
            if let Some(Value::Array(rest)) = node.get("required") {
                required.extend(rest.iter().cloned());
            }
            node.insert("required".to_owned(), Value::Array(required));
        }
        if let Some(defs) = doc.get("defs") {
            let loc = root.key("defs");
            match defs.as_object() {
                Some(defs) => {
                    let defs = defs
                        .iter()
                        .map(|(name, value)| {
                            (name.clone(), self.field_value(value, &loc.key(name), 0))
                        })
                        .collect();
                    node.insert("$defs".to_owned(), Value::Object(defs));
                }
                None => self.problem(&loc, "must be a mapping"),
            }
        }
        if let Some(examples) = doc.get("examples") {
            let loc = root.key("examples");
            match examples.as_array() {
                Some(rows) => {
                    for (index, row) in rows.iter().enumerate() {
                        if !row.is_object() {
                            self.problem(&loc.index(index), "an example row must be a mapping");
                        }
                    }
                    node.insert("examples".to_owned(), examples.clone());
                }
                None => self.problem(&loc, "must be a list of rows"),
            }
        }
        self.merge_json(&mut node, doc, &root);
        node.entry("$schema")
            .or_insert_with(|| Value::String(DRAFT.to_owned()));
        Value::Object(node)
    }

    /// Checks a document's `type` and `version`, and gives the type, its
    /// version and its `$id` when they make a published type.
    fn published_type(
        &mut self,
        doc: &Map<String, Value>,
        root: &Loc,
    ) -> Option<(String, u64, String)> {
        let kind = doc.get("type");
        let version = doc.get("version");
        let mut ok = true;
        if version.is_some() && kind.is_none() {
            self.problem(&root.key("version"), "version needs type");
            return None;
        }
        let kind = kind?;
        let kind = match kind.as_str() {
            Some(text) if is_type_identifier(text) => Some(text.to_owned()),
            Some(text) => {
                self.problem(&root.key("type"), format!("bad type identifier {text}"));
                None
            }
            None => {
                self.problem(&root.key("type"), "bad type identifier: must be a string");
                None
            }
        };
        let version = match version {
            None => {
                self.problem(&root.key("type"), "type needs version");
                None
            }
            Some(value) => match value.as_u64().filter(|v| *v >= 1) {
                Some(v) => Some(v),
                None => {
                    self.problem(
                        &root.key("version"),
                        "version must be an integer of 1 or more",
                    );
                    None
                }
            },
        };
        if self.options.base.is_none() {
            self.problem(&root.key("type"), "a published type needs the base option");
            ok = false;
        }
        let (kind, version) = (kind?, version?);
        if !ok {
            return None;
        }
        let base = self.options.base.as_deref().unwrap_or_default();
        let id = format!("{base}{kind}/v{version}.json");
        Some((kind, version, id))
    }

    /// Merges a mapping's `json` into its node.
    fn merge_json(
        &mut self,
        node: &mut Map<String, Value>,
        mapping: &Map<String, Value>,
        loc: &Loc,
    ) {
        let Some(json) = mapping.get("json") else {
            return;
        };
        let loc = loc.key("json");
        let Some(json) = json.as_object() else {
            self.problem(&loc, "must be a mapping");
            return;
        };
        for (key, value) in json {
            if key == "allOf" && mapping.contains_key("rules") {
                self.problem(&loc.key(key), "json sets allOf beside rules");
            } else if node.contains_key(key) {
                self.problem(&loc.key(key), format!("{key} is already set"));
            } else {
                node.insert(key.clone(), value.clone());
            }
        }
    }

    fn object_of(
        &mut self,
        fields: &Value,
        loc: &Loc,
        depth: usize,
        node: &mut Map<String, Value>,
    ) {
        let Some(fields) = fields.as_object() else {
            self.problem(loc, "must be a mapping");
            return;
        };
        let mut properties = Map::new();
        let mut required = Vec::new();
        for (raw, value) in fields {
            let (name, optional) = match raw.strip_suffix('?') {
                Some(name) => (name, true),
                None => (raw.as_str(), false),
            };
            let field_loc = loc.key(raw);
            if name.is_empty() {
                self.problem(&field_loc, "a field needs a name");
                continue;
            }
            if self.published && depth == 0 && PUBLISHED_PROPERTIES.contains(&name) {
                self.problem(&field_loc, format!("{name} is set by the published type"));
                continue;
            }
            let expanded = self.field_value(value, &field_loc, depth + 1);
            if properties.insert(name.to_owned(), expanded).is_some() {
                self.problem(&field_loc, format!("{name} is listed twice"));
            }
            if !optional {
                required.push(Value::String(name.to_owned()));
            }
        }
        node.insert("type".to_owned(), json!("object"));
        node.insert("properties".to_owned(), Value::Object(properties));
        if !required.is_empty() {
            node.insert("required".to_owned(), Value::Array(required));
        }
    }

    fn field_value(&mut self, value: &Value, loc: &Loc, depth: usize) -> Value {
        if depth > MAX_DEPTH {
            self.problem(loc, "nested too deep");
            return json!({});
        }
        match value {
            Value::String(text) => {
                let (expr, description) = match text.find(" -- ") {
                    Some(cut) => (&text[..cut], Some(&text[cut + 4..])),
                    None => (text.as_str(), None),
                };
                let (expr, labels) = Self::split_labels(expr);
                let before = self.problems.len();
                let mut node = self.expression(expr, loc);
                if self.problems.len() > before
                    && expr.split_whitespace().any(|token| token.starts_with('@'))
                {
                    self.problems.truncate(before);
                    self.problem(loc, "bad label: labels go at the end of the expression");
                }
                if let Value::Object(object) = &mut node {
                    if let Some(description) = description {
                        object.insert("description".to_owned(), json!(description));
                    }
                    if !labels.is_empty() {
                        object.insert("x-data".to_owned(), json!(labels));
                    }
                }
                node
            }
            Value::Object(mapping) => self.field_mapping(mapping, loc, depth),
            _ => {
                self.problem(loc, "expected a type expression or a mapping");
                json!({})
            }
        }
    }

    /// Splits trailing `@<category>` tokens off a field expression. A token
    /// is a label only when the text after `@` is a label key; anything
    /// else, such as `@b)?` ending an enum or `@y/` ending a pattern, is the
    /// expression parser's.
    fn split_labels(expr: &str) -> (&str, Vec<String>) {
        let mut rest = expr.trim_end();
        let mut labels = Vec::new();
        loop {
            let start = rest.rfind(char::is_whitespace).map_or(0, |at| at + 1);
            let token = &rest[start..];
            match token.strip_prefix('@') {
                Some(key) if is_label_key(key) => labels.push(key.to_owned()),
                _ => break,
            }
            rest = rest[..start].trim_end();
        }
        labels.reverse();
        (rest, labels)
    }

    fn field_mapping(&mut self, mapping: &Map<String, Value>, loc: &Loc, depth: usize) -> Value {
        for key in mapping.keys() {
            if !FIELD_KEYS.contains(&key.as_str()) {
                self.problem(&loc.key(key), format!("unknown key {key}"));
            }
        }
        if mapping.contains_key("items") {
            for other in ["type", "fields"] {
                if mapping.contains_key(other) {
                    self.problem(loc, format!("items can't go with {other}"));
                }
            }
        }
        let mut node = Map::new();
        if let Some(fields) = mapping.get("fields") {
            self.object_of(fields, &loc.key("fields"), depth, &mut node);
            if let Some(kind) = mapping.get("type") {
                if kind == "object?" {
                    node.insert("type".to_owned(), json!(["object", "null"]));
                } else {
                    self.problem(&loc.key("type"), "next to fields, type can only be object?");
                }
            }
        } else if let Some(kind) = mapping.get("type") {
            let type_loc = loc.key("type");
            match kind.as_str() {
                Some(text) => {
                    if let Value::Object(object) = self.expression(text, &type_loc) {
                        node = object;
                    }
                }
                None => self.problem(&type_loc, "must be a type expression"),
            }
        } else if let Some(items) = mapping.get("items") {
            let items = self.field_value(items, &loc.key("items"), depth + 1);
            node.insert("type".to_owned(), json!("array"));
            node.insert("items".to_owned(), items);
        }
        if let Some(description) = mapping.get("description") {
            if description.is_string() {
                node.insert("description".to_owned(), description.clone());
            } else {
                self.problem(&loc.key("description"), "must be a string");
            }
        }
        if let Some(examples) = mapping.get("examples") {
            if examples.is_array() {
                node.insert("examples".to_owned(), examples.clone());
            } else {
                self.problem(&loc.key("examples"), "must be a list");
            }
        }
        let nullable = mapping.get("type") == Some(&json!("object?"));
        self.rules(mapping, loc, nullable, &mut node);
        self.merge_json(&mut node, mapping, loc);
        Value::Object(node)
    }

    fn expression(&mut self, text: &str, loc: &Loc) -> Value {
        let mut parser = ExprParser {
            s: text.as_bytes(),
            text,
            i: 0,
            depth: 0,
            own: self.own,
            title: self.title.as_deref(),
            options: self.options,
        };
        match parser.parse() {
            Ok(value) => value,
            Err(message) => {
                self.problem(loc, format!("{message} in `{text}`"));
                json!({})
            }
        }
    }
}

struct ExprParser<'a> {
    s: &'a [u8],
    text: &'a str,
    i: usize,
    depth: usize,
    own: &'a str,
    title: Option<&'a str>,
    options: &'a Options,
}

struct Expr {
    node: Map<String, Value>,
    bare: bool,
}

impl ExprParser<'_> {
    fn parse(&mut self) -> Result<Value, String> {
        let expr = self.union()?;
        if let Some(ch) = self.peek() {
            return Err(format!("unexpected {}", ch as char));
        }
        Ok(Value::Object(expr.node))
    }

    fn peek(&mut self) -> Option<u8> {
        while self.s.get(self.i) == Some(&b' ') {
            self.i += 1;
        }
        self.s.get(self.i).copied()
    }

    fn expect(&mut self, ch: u8) -> Result<(), String> {
        if self.peek() != Some(ch) {
            return Err(format!("expected {}", ch as char));
        }
        self.i += 1;
        Ok(())
    }

    // The text between ( and its matching ), skipping parentheses inside double quotes.
    fn args(&mut self) -> Result<&str, String> {
        self.expect(b'(')?;
        let start = self.i;
        let mut depth = 1;
        let mut quoted = false;
        while self.i < self.s.len() {
            let ch = self.s[self.i];
            if quoted {
                if ch == b'\\' {
                    self.i += 1;
                } else if ch == b'"' {
                    quoted = false;
                }
            } else if ch == b'"' {
                quoted = true;
            } else if ch == b'(' {
                depth += 1;
            } else if ch == b')' {
                depth -= 1;
                if depth == 0 {
                    let inner = &self.text[start..self.i];
                    self.i += 1;
                    return Ok(inner);
                }
            }
            self.i += 1;
        }
        Err("unclosed (".to_owned())
    }

    fn union(&mut self) -> Result<Expr, String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("nested too deep".to_owned());
        }
        let mut parts = vec![self.postfix()?];
        while self.peek() == Some(b'|') {
            self.i += 1;
            parts.push(self.postfix()?);
        }
        self.depth -= 1;
        if parts.len() == 1 {
            return Ok(parts.pop().expect("one part"));
        }
        let node = if parts.iter().all(|part| part.bare) {
            let types = parts
                .into_iter()
                .map(|part| part.node["type"].clone())
                .collect();
            Map::from_iter([("type".to_owned(), Value::Array(types))])
        } else {
            let members = parts
                .into_iter()
                .map(|part| Value::Object(part.node))
                .collect();
            Map::from_iter([("anyOf".to_owned(), Value::Array(members))])
        };
        Ok(Expr { node, bare: false })
    }

    fn postfix(&mut self) -> Result<Expr, String> {
        let mut expr = self.primary()?;
        let mut count = 0;
        loop {
            if self.s[self.i..].starts_with(b"[]") {
                self.i += 2;
                expr = Expr {
                    node: Map::from_iter([
                        ("type".to_owned(), json!("array")),
                        ("items".to_owned(), Value::Object(expr.node)),
                    ]),
                    bare: false,
                };
            } else if self.s.get(self.i) == Some(&b'?') {
                self.i += 1;
                expr = Expr {
                    node: nullable(expr.node),
                    bare: false,
                };
            } else {
                return Ok(expr);
            }
            count += 1;
            if count > MAX_DEPTH {
                return Err("nested too deep".to_owned());
            }
        }
    }

    fn primary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some(b'(') => {
                self.i += 1;
                let expr = self.union()?;
                self.expect(b')')?;
                return Ok(expr);
            }
            Some(b'/') => {
                self.i += 1;
                let start = self.i;
                while self.i < self.s.len() && self.s[self.i] != b'/' {
                    if self.s[self.i] == b'\\' {
                        self.i += 1;
                    }
                    self.i += 1;
                }
                if self.i >= self.s.len() {
                    return Err("unclosed /regex/".to_owned());
                }
                let pattern = &self.text[start..self.i];
                self.i += 1;
                return Ok(plain(json!({"type": "string", "pattern": pattern})));
            }
            _ => {}
        }
        let start = self.i;
        if !self
            .s
            .get(self.i)
            .is_some_and(|ch| ch.is_ascii_alphabetic() || *ch == b'_')
        {
            return Err("expected a type".to_owned());
        }
        while self
            .s
            .get(self.i)
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'.' | b'-'))
        {
            self.i += 1;
        }
        let word = &self.text[start..self.i];
        if PRIMITIVES.contains(&word) {
            if self.s.get(self.i) != Some(&b'(') {
                return Ok(Expr {
                    node: Map::from_iter([("type".to_owned(), json!(word))]),
                    bare: true,
                });
            }
            let inner = self.args()?.trim();
            return match word {
                "string" if !inner.is_empty() => {
                    Ok(plain(json!({"type": "string", "format": inner})))
                }
                "string" => Err("string() needs a format".to_owned()),
                "integer" | "number" => range(word, inner).map(plain),
                _ => Err(format!("{word} takes no arguments")),
            };
        }
        match word {
            "ref" => {
                let kinds = split_list(self.args()?);
                if kinds.is_empty() {
                    return Err("ref needs a kind".to_owned());
                }
                for kind in &kinds {
                    if !is_kind(kind) {
                        return Err(format!(
                            "ref kind {kind} must be lowercase letters and hyphens"
                        ));
                    }
                }
                let kinds: Vec<Value> = kinds.into_iter().map(Value::String).collect();
                let refs = if kinds.len() == 1 {
                    kinds.into_iter().next().expect("one kind")
                } else {
                    Value::Array(kinds)
                };
                Ok(plain(
                    json!({"$ref": self.target("common", "refString"), "ref": refs}),
                ))
            }
            "known" => {
                let values = split_list(self.args()?)
                    .into_iter()
                    .map(|value| enum_value(&value))
                    .collect::<Result<Vec<_>, _>>()?;
                if values.is_empty() {
                    return Err("known needs a value".to_owned());
                }
                if !values.iter().all(Value::is_string) {
                    return Err("known values must be strings".to_owned());
                }
                Ok(plain(json!({"type": "string", "examples": values})))
            }
            "enum" => {
                let values = split_list(self.args()?)
                    .into_iter()
                    .map(|value| enum_value(&value))
                    .collect::<Result<Vec<_>, _>>()?;
                if values.is_empty() {
                    return Err("enum needs a value".to_owned());
                }
                let mut node = Map::new();
                if values.iter().all(Value::is_string) {
                    node.insert("type".to_owned(), json!("string"));
                } else if values.iter().all(|v| v.is_i64() || v.is_u64()) {
                    node.insert("type".to_owned(), json!("integer"));
                } else if values.iter().all(Value::is_number) {
                    node.insert("type".to_owned(), json!("number"));
                }
                node.insert("enum".to_owned(), Value::Array(values));
                Ok(Expr { node, bare: false })
            }
            _ => {
                let (schema, name) = match word.split_once('.') {
                    Some((schema, name))
                        if name.starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_') =>
                    {
                        (schema, name)
                    }
                    Some(_) => return Err("expected a name after .".to_owned()),
                    None => ("common", word),
                };
                Ok(plain(json!({"$ref": self.target(schema, name)})))
            }
        }
    }

    fn target(&self, schema: &str, name: &str) -> String {
        if schema == self.own || Some(schema) == self.title {
            format!("#/$defs/{name}")
        } else {
            format!("{}#/$defs/{name}", self.options.location_of(schema))
        }
    }
}

fn plain(node: Value) -> Expr {
    let Value::Object(node) = node else {
        unreachable!("expressions are objects")
    };
    Expr { node, bare: false }
}

fn nullable(mut node: Map<String, Value>) -> Map<String, Value> {
    match node.get_mut("type") {
        Some(kind) => {
            let mut types = match kind.take() {
                Value::Array(types) => types,
                other => vec![other],
            };
            if !types.contains(&json!("null")) {
                types.push(json!("null"));
            }
            *kind = Value::Array(types);
            if let Some(Value::Array(values)) = node.get_mut("enum") {
                if !values.contains(&Value::Null) {
                    values.push(Value::Null);
                }
            }
            node
        }
        None => Map::from_iter([(
            "anyOf".to_owned(),
            json!([Value::Object(node), {"type": "null"}]),
        )]),
    }
}

fn range(word: &str, inner: &str) -> Result<Value, String> {
    let Some((min, max)) = inner.split_once("..") else {
        return Err("expected <min>..<max>".to_owned());
    };
    let (min, max) = (min.trim(), max.trim());
    if min.is_empty() && max.is_empty() {
        return Err("a range needs at least one bound".to_owned());
    }
    let mut node = Map::from_iter([("type".to_owned(), json!(word))]);
    for (key, bound) in [("minimum", min), ("maximum", max)] {
        if bound.is_empty() {
            continue;
        }
        let number = parse_number(bound).ok_or_else(|| format!("{bound} isn't a number"))?;
        node.insert(key.to_owned(), Value::Number(number));
    }
    Ok(Value::Object(node))
}

fn parse_number(text: &str) -> Option<Number> {
    if !is_json_number(text) {
        return None;
    }
    serde_json::from_str(text).ok()
}

fn split_list(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if quoted {
            current.push(ch);
            if ch == '\\' {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
            current.push(ch);
        } else if ch == ',' {
            out.push(current.trim().to_owned());
            current.clear();
        } else {
            current.push(ch);
        }
    }
    out.push(current.trim().to_owned());
    out.retain(|item| !item.is_empty());
    out
}

/// Reads one value as `enum`'s values are read (§ Type expressions): a
/// JSON string in double quotes, a JSON number, or the text as written.
/// Values in single quotes, and `null`, are refused. Rules read their
/// values with this too.
pub(crate) fn enum_value(value: &str) -> Result<Value, String> {
    if value.starts_with('"') {
        return serde_json::from_str::<String>(value)
            .map(Value::String)
            .map_err(|_| format!("bad quoted value {value}"));
    }
    if let Some(inner) = value.strip_prefix('\'') {
        let inner = inner.strip_suffix('\'').unwrap_or(inner);
        return Err(format!(
            "enum values are quoted with double quotes: write \"{inner}\", not {value}"
        ));
    }
    if value == "null" {
        return Err("null can't be an enum value; to allow null, put ? after enum(...)".to_owned());
    }
    if is_json_number(value) {
        return parse_number(value)
            .map(Value::Number)
            .ok_or_else(|| format!("{value} is out of range"));
    }
    Ok(Value::String(value.to_owned()))
}

fn is_kind(kind: &str) -> bool {
    kind.starts_with(|ch: char| ch.is_ascii_lowercase())
        && kind.chars().all(|ch| ch.is_ascii_lowercase() || ch == '-')
}

/// A label category: dotted lowercase keys, `[a-z0-9_]+(\.[a-z0-9_]+)*`.
fn is_label_key(key: &str) -> bool {
    !key.is_empty()
        && key.split('.').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        })
}

/// A name a published type's title can give the schema itself: a word
/// without dots, so `<title>.<name>` reads as a reference to it.
fn is_schema_name(title: &str) -> bool {
    is_word(title) && !title.contains('.')
}

fn is_word(word: &str) -> bool {
    word.starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_')
        && word
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
}

// ---------- Normalization ----------

fn normalize_node(node: &Value) -> Value {
    let Some(object) = node.as_object() else {
        return node.clone();
    };
    let mut out = Map::new();
    for (key, value) in object {
        let value = match key.as_str() {
            "additionalProperties" if value == &Value::Bool(true) => continue,
            "required" => match value.as_array() {
                Some(names) if names.iter().all(Value::is_string) => {
                    let mut names = names.clone();
                    names.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                    Value::Array(names)
                }
                _ => value.clone(),
            },
            "properties" | "$defs" => match value.as_object() {
                Some(children) => Value::Object(
                    children
                        .iter()
                        .map(|(name, child)| (name.clone(), normalize_node(child)))
                        .collect(),
                ),
                None => value.clone(),
            },
            "items" => normalize_node(value),
            "anyOf" => match value.as_array() {
                Some(members) => Value::Array(members.iter().map(normalize_node).collect()),
                None => value.clone(),
            },
            _ => value.clone(),
        };
        out.insert(key.clone(), value);
    }
    Value::Object(out)
}

// ---------- Generation ----------

struct Generator<'a> {
    own: &'a str,
    options: &'a Options,
    published: bool,
    /// The body's `$defs`, for rule paths that step through a local ref.
    defs: &'a Map<String, Value>,
}

/// A published type's identifier and version, when `body` is one under the
/// options' base: `$id`, the `$type` and `version` consts, and both in
/// `required`, all agreeing.
fn published_parts(body: &Map<String, Value>, options: &Options) -> Option<(String, u64)> {
    let base = options.base.as_deref()?;
    let properties = body.get("properties")?.as_object()?;
    let kind = properties.get("$type")?.as_object()?;
    let version = properties.get("version")?.as_object()?;
    if kind.len() != 1 || version.len() != 1 {
        return None;
    }
    let kind = kind.get("const")?.as_str()?;
    let version = version.get("const")?.as_u64()?;
    if !is_type_identifier(kind) || version == 0 {
        return None;
    }
    if body.get("$id")?.as_str()? != format!("{base}{kind}/v{version}.json") {
        return None;
    }
    if body.get("type") != Some(&json!("object")) {
        return None;
    }
    let required = body.get("required")?.as_array()?;
    if !required.contains(&json!("$type")) || !required.contains(&json!("version")) {
        return None;
    }
    Some((kind.to_owned(), version))
}

struct Text {
    text: String,
    union: bool,
}

impl Text {
    fn atom(&self) -> String {
        if self.union {
            format!("({})", self.text)
        } else {
            self.text.clone()
        }
    }
}

const COVERED: [&str; 10] = [
    "type", "format", "pattern", "minimum", "maximum", "$ref", "ref", "enum", "items", "anyOf",
];

impl Generator<'_> {
    fn expander(&self) -> Expander<'_> {
        let mut expander = Expander::new(self.own, None, self.options);
        expander.defs = Cow::Borrowed(self.defs);
        expander
    }

    fn expands_to(&self, value: &Value, node: &Map<String, Value>) -> bool {
        let mut expander = self.expander();
        let expanded = expander.field_value(value, &Loc::root(), 0);
        expander.problems.is_empty() && expanded.as_object() == Some(node)
    }

    fn document(&self, body: &Map<String, Value>) -> Map<String, Value> {
        let mut rest = body.clone();
        let mut doc = Map::new();
        if rest.get("$schema") == Some(&json!(DRAFT)) {
            rest.remove("$schema");
        }
        if let Some((kind, version)) = published_parts(body, self.options) {
            doc.insert("type".to_owned(), json!(kind));
            doc.insert("version".to_owned(), json!(version));
            rest.remove("$id");
            if let Some(Value::Object(properties)) = rest.get_mut("properties") {
                for key in PUBLISHED_PROPERTIES {
                    properties.remove(key);
                }
            }
            if let Some(Value::Array(required)) = rest.get_mut("required") {
                required.retain(|name| !PUBLISHED_PROPERTIES.iter().any(|key| name == key));
            }
            if rest
                .get("required")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            {
                rest.remove("required");
            }
            if rest
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(Map::is_empty)
                && !rest.contains_key("required")
            {
                rest.remove("properties");
                rest.remove("type");
            }
        }
        for key in ["title", "description"] {
            if rest.get(key).is_some_and(Value::is_string) {
                doc.insert(key.to_owned(), rest.remove(key).expect("checked"));
            }
        }
        if let Some(fields) = self.fields_of(&rest, false) {
            doc.insert("fields".to_owned(), Value::Object(fields));
            if let Some(rules) = self.rules_beside(&rest) {
                doc.insert("rules".to_owned(), Value::Array(rules));
                rest.remove("allOf");
            }
            for key in ["type", "properties", "required"] {
                rest.remove(key);
            }
        }
        if let Some(Value::Object(defs)) = rest.get("$defs") {
            let generated: Option<Map<String, Value>> = defs
                .iter()
                .map(|(name, def)| Some((name.clone(), self.field(def)?)))
                .collect();
            if let Some(generated) = generated {
                doc.insert("defs".to_owned(), Value::Object(generated));
                rest.remove("$defs");
            }
        }
        if let Some(Value::Array(rows)) = rest.get("examples") {
            if rows.iter().all(Value::is_object) {
                doc.insert(
                    "examples".to_owned(),
                    rest.remove("examples").expect("checked"),
                );
            }
        }
        if !rest.is_empty() {
            doc.insert("json".to_owned(), Value::Object(rest));
        }
        let mut expander = self.expander();
        let expanded = normalize(&expander.document(&Value::Object(doc.clone())));
        if expander.problems.is_empty() && expanded.as_object() == Some(body) {
            return doc;
        }
        let mut rest = body.clone();
        if rest.get("$schema") == Some(&json!(DRAFT)) {
            rest.remove("$schema");
        }
        if rest.is_empty() {
            Map::new()
        } else {
            Map::from_iter([("json".to_owned(), Value::Object(rest))])
        }
    }

    // The short-form `fields` for an object node, when its type, properties and required allow one.
    fn fields_of(&self, node: &Map<String, Value>, allow_null: bool) -> Option<Map<String, Value>> {
        let object = json!("object");
        let nullable = json!(["object", "null"]);
        match node.get("type") {
            Some(kind) if *kind == object => {}
            Some(kind) if allow_null && *kind == nullable => {}
            _ => return None,
        }
        let properties = node.get("properties")?.as_object()?;
        let required: Vec<&str> = match node.get("required") {
            None => Vec::new(),
            Some(Value::Array(names)) if !names.is_empty() => {
                names.iter().map(Value::as_str).collect::<Option<_>>()?
            }
            Some(_) => return None,
        };
        let mut fields = Map::new();
        for (name, property) in properties {
            let is_required = required.contains(&name.as_str());
            if is_required && name.ends_with('?') {
                return None;
            }
            let key = if is_required {
                name.clone()
            } else {
                format!("{name}?")
            };
            fields.insert(key, self.field(property)?);
        }
        if required.iter().any(|name| !properties.contains_key(*name)) {
            return None;
        }
        Some(fields)
    }

    fn field(&self, node: &Value) -> Option<Value> {
        let node = node.as_object()?;
        let mut rest = node.clone();
        let description = match rest.get("description") {
            Some(Value::String(_)) => rest.remove("description"),
            _ => None,
        };
        let examples = match rest.get("examples") {
            Some(Value::Array(_)) => rest.remove("examples"),
            _ => None,
        };
        let mapping = |kind: Option<Value>, extra: Vec<(&str, Value)>, json: Map<String, Value>| {
            let mut out = Map::new();
            if let Some(description) = &description {
                out.insert("description".to_owned(), description.clone());
            }
            if let Some(kind) = kind {
                out.insert("type".to_owned(), kind);
            }
            for (key, value) in extra {
                out.insert(key.to_owned(), value);
            }
            if let Some(examples) = &examples {
                out.insert("examples".to_owned(), examples.clone());
            }
            if !json.is_empty() {
                out.insert("json".to_owned(), Value::Object(json));
            }
            Value::Object(out)
        };
        let mut candidates = Vec::new();
        let labels: Vec<&str> = match rest.get("x-data") {
            Some(Value::Array(items))
                if !items.is_empty()
                    && items
                        .iter()
                        .all(|item| item.as_str().is_some_and(is_label_key)) =>
            {
                items.iter().filter_map(Value::as_str).collect()
            }
            _ => Vec::new(),
        };
        let mut bare = rest.clone();
        if !labels.is_empty() {
            bare.remove("x-data");
        }
        let suffix: String = labels.iter().map(|label| format!(" @{label}")).collect();
        if let Some(text) = self.known(&bare, examples.as_ref()) {
            match &description {
                None => candidates.push(Value::String(format!("{text}{suffix}"))),
                Some(Value::String(line)) if !line.contains('\n') => {
                    candidates.push(Value::String(format!("{text}{suffix} -- {line}")));
                }
                _ => {}
            }
        }
        if let Some(text) = self.expr(&bare) {
            match (&description, &examples) {
                (None, None) => candidates.push(Value::String(format!("{}{suffix}", text.text))),
                (Some(Value::String(line)), None)
                    if !line.contains('\n') && !text.text.contains(" -- ") =>
                {
                    candidates.push(Value::String(format!("{}{suffix} -- {line}", text.text)));
                }
                _ => {}
            }
            let mut json = Map::new();
            if let Some(data) = rest.get("x-data").filter(|_| !labels.is_empty()) {
                json.insert("x-data".to_owned(), data.clone());
            }
            candidates.push(mapping(Some(Value::String(text.text)), vec![], json));
        }
        if let Some(fields) = self.fields_of(&rest, true) {
            let kind = (rest["type"] != json!("object")).then(|| json!("object?"));
            let mut json = rest.clone();
            for key in ["type", "properties", "required"] {
                json.remove(key);
            }
            let mut extra = vec![("fields", Value::Object(fields))];
            if let Some(rules) = self.rules_beside(&rest) {
                extra.push(("rules", Value::Array(rules)));
                json.remove("allOf");
            }
            candidates.push(mapping(kind, extra, json));
        }
        let (covered, uncovered): (Map<String, Value>, Map<String, Value>) = rest
            .clone()
            .into_iter()
            .partition(|(key, _)| COVERED.contains(&key.as_str()));
        if !covered.is_empty() && !uncovered.is_empty() {
            if let Some(text) = self.expr(&covered) {
                candidates.push(mapping(Some(Value::String(text.text)), vec![], uncovered));
            }
        }
        if rest.get("type") == Some(&json!("array")) {
            if let Some(items) = rest.get("items").and_then(|items| self.field(items)) {
                let mut json = rest.clone();
                json.remove("type");
                json.remove("items");
                candidates.push(mapping(None, vec![("items", items)], json));
            }
        }
        for candidate in candidates {
            if self.expands_to(&candidate, node) {
                return Some(candidate);
            }
        }
        Some(mapping(None, vec![], rest))
    }

    /// `known(…)` for a property of a published type that is exactly a
    /// string (or nullable string) with string examples.
    fn known(&self, node: &Map<String, Value>, examples: Option<&Value>) -> Option<String> {
        if !self.published {
            return None;
        }
        known_text(node, examples)
    }

    /// `rules` for an object node with `type: object` and an `allOf` that
    /// is all rule members ([`Generator::rules_of`]).
    fn rules_beside(&self, node: &Map<String, Value>) -> Option<Vec<Value>> {
        let (entries, properties) = rule_holder(node).ok()?;
        self.rules_of(entries, properties)
    }

    fn expr(&self, node: &Map<String, Value>) -> Option<Text> {
        let only = |keys: &[&str]| node.keys().all(|key| keys.contains(&key.as_str()));
        let atom = |text: String| Some(Text { text, union: false });
        if let Some(members) = node.get("anyOf") {
            if node.len() != 1 {
                return None;
            }
            let members = members.as_array()?;
            if members.len() < 2 {
                return None;
            }
            let null = json!({"type": "null"});
            if members.len() == 2 && members[1] == null {
                let first = members[0].as_object()?;
                if !first.contains_key("type") {
                    return atom(format!("{}?", self.expr(first)?.atom()));
                }
            }
            let parts = members
                .iter()
                .map(|member| Some(self.expr(member.as_object()?)?.atom()))
                .collect::<Option<Vec<_>>>()?;
            return Some(Text {
                text: parts.join("|"),
                union: true,
            });
        }
        if let Some(target) = node.get("$ref") {
            let target = target.as_str()?;
            if let Some(kinds) = node.get("ref") {
                if !only(&["$ref", "ref"]) || target != self.ref_target("common", "refString") {
                    return None;
                }
                let kinds: Vec<&str> = match kinds {
                    Value::String(kind) => vec![kind],
                    Value::Array(kinds) if kinds.len() > 1 => {
                        kinds.iter().map(Value::as_str).collect::<Option<_>>()?
                    }
                    _ => return None,
                };
                return atom(format!("ref({})", kinds.join(", ")));
            }
            if !only(&["$ref"]) {
                return None;
            }
            return atom(self.ref_name(target)?);
        }
        if let Some(Value::Array(types)) = node.get("type") {
            if types.len() >= 2 && types.last() == Some(&json!("null")) {
                let mut inner = node.clone();
                let rest: Vec<Value> = types[..types.len() - 1].to_vec();
                inner.insert(
                    "type".to_owned(),
                    if rest.len() == 1 {
                        rest[0].clone()
                    } else {
                        Value::Array(rest)
                    },
                );
                if let Some(Value::Array(values)) = node.get("enum") {
                    if values.last() != Some(&Value::Null) {
                        return None;
                    }
                    inner.insert(
                        "enum".to_owned(),
                        Value::Array(values[..values.len() - 1].to_vec()),
                    );
                }
                return atom(format!("{}?", self.expr(&inner)?.atom()));
            }
            if !only(&["type"]) {
                return None;
            }
            let names = types
                .iter()
                .map(|kind| kind.as_str().filter(|kind| PRIMITIVES.contains(kind)))
                .collect::<Option<Vec<_>>>()?;
            if names.len() < 2 {
                return None;
            }
            return Some(Text {
                text: names.join("|"),
                union: true,
            });
        }
        if let Some(values) = node.get("enum") {
            if !only(&["type", "enum"]) {
                return None;
            }
            let values = values
                .as_array()?
                .iter()
                .map(enum_text)
                .collect::<Option<Vec<_>>>()?;
            if values.is_empty() {
                return None;
            }
            return atom(format!("enum({})", values.join(", ")));
        }
        let kind = node.get("type")?.as_str()?;
        match kind {
            "string" if only(&["type"]) => atom("string".to_owned()),
            "string" if only(&["type", "format"]) => {
                let format = node.get("format")?.as_str()?;
                atom(format!("string({format})"))
            }
            "string" if only(&["type", "pattern"]) => {
                let pattern = node.get("pattern")?.as_str()?;
                atom(format!("/{pattern}/"))
            }
            "integer" | "number" if only(&["type", "minimum", "maximum"]) => {
                if node.len() == 1 {
                    return atom(kind.to_owned());
                }
                let bound = |key: &str| match node.get(key) {
                    None => Some(String::new()),
                    Some(Value::Number(number)) => Some(number.to_string()),
                    Some(_) => None,
                };
                atom(format!(
                    "{kind}({}..{})",
                    bound("minimum")?,
                    bound("maximum")?
                ))
            }
            "array" if only(&["type", "items"]) => {
                let items = self.expr(node.get("items")?.as_object()?)?;
                atom(format!("{}[]", items.atom()))
            }
            "boolean" | "object" | "null" if only(&["type"]) => atom(kind.to_owned()),
            _ => None,
        }
    }

    fn ref_target(&self, schema: &str, name: &str) -> String {
        if schema == self.own {
            format!("#/$defs/{name}")
        } else {
            format!("{}#/$defs/{name}", self.options.location_of(schema))
        }
    }

    fn ref_name(&self, target: &str) -> Option<String> {
        let (schema, name) = match target.strip_prefix("#/$defs/") {
            Some(name) => (self.own.to_owned(), name),
            None => {
                let (file, name) = target.split_once("#/$defs/")?;
                (self.options.schema_at(file)?, name)
            }
        };
        let schema = schema.as_str();
        if !is_word(name) {
            return None;
        }
        if schema == "common" && !name.contains('.') && !RESERVED.contains(&name) {
            Some(name.to_owned())
        } else {
            Some(format!("{schema}.{name}"))
        }
    }
}

/// `known(…)`, or `known(…)?`, for a node (without `description` and
/// `examples`) that is exactly a string, or a nullable string, whose
/// examples are strings. Generation writes it so only in a published type;
/// a rule's `G(a)` takes such a field as not a plain string in any schema.
fn known_text(node: &Map<String, Value>, examples: Option<&Value>) -> Option<String> {
    if node.len() != 1 {
        return None;
    }
    let nullable = match node.get("type")? {
        Value::String(kind) if kind == "string" => false,
        kind if *kind == json!(["string", "null"]) => true,
        _ => return None,
    };
    let values = examples?.as_array()?;
    if values.is_empty() || !values.iter().all(Value::is_string) {
        return None;
    }
    let values = values.iter().map(enum_text).collect::<Option<Vec<_>>>()?;
    let mark = if nullable { "?" } else { "" };
    Some(format!("known({}){mark}", values.join(", ")))
}

fn enum_text(value: &Value) -> Option<String> {
    match value {
        Value::Number(number) => Some(number.to_string()),
        Value::String(text) => {
            let quote = text.is_empty()
                || text.trim() != text
                || text.contains([',', '(', ')', '"'])
                || text.starts_with(['\'', '@'])
                || text == "null"
                || is_json_number(text);
            Some(if quote {
                serde_json::to_string(text).expect("strings serialize")
            } else {
                text.clone()
            })
        }
        _ => None,
    }
}

// ---------- Emission ----------

#[derive(Clone)]
enum Order {
    Document(Vec<String>),
    Fields,
    Defs,
    Field,
    Row(Vec<String>),
    Rows(Vec<String>),
    Sorted,
}

fn field_order(fields: &Map<String, Value>) -> Vec<String> {
    let mut keys: Vec<&String> = fields.keys().collect();
    keys.sort_by_key(|key| field_sort_key(key));
    keys.into_iter()
        .map(|key| key.strip_suffix('?').unwrap_or(key).to_owned())
        .collect()
}

fn field_sort_key(key: &str) -> (bool, &str) {
    match key.strip_suffix('?') {
        Some(name) => (true, name),
        None => (false, key),
    }
}

fn ordered<'a>(map: &'a Map<String, Value>, order: &Order) -> Vec<(&'a String, &'a Value)> {
    let mut entries: Vec<(&String, &Value)> = map.iter().collect();
    let fixed =
        |list: &[&str], key: &str| list.iter().position(|k| *k == key).unwrap_or(list.len());
    match order {
        Order::Document(_) => entries.sort_by_key(|(key, _)| fixed(&DOC_KEYS, key)),
        Order::Field => entries.sort_by_key(|(key, _)| fixed(&FIELD_KEYS, key)),
        Order::Fields => entries.sort_by(|a, b| field_sort_key(a.0).cmp(&field_sort_key(b.0))),
        Order::Row(fields) => entries.sort_by(|a, b| {
            let rank = |key: &str| fields.iter().position(|f| f == key).unwrap_or(fields.len());
            (rank(a.0), a.0).cmp(&(rank(b.0), b.0))
        }),
        Order::Defs | Order::Rows(_) | Order::Sorted => entries.sort_by(|a, b| a.0.cmp(b.0)),
    }
    entries
}

fn child(order: &Order, key: &str) -> Order {
    match (order, key) {
        (Order::Document(_), "fields") | (Order::Field, "fields") => Order::Fields,
        (Order::Document(_), "defs") => Order::Defs,
        (Order::Document(fields), "examples") => Order::Rows(fields.clone()),
        (Order::Fields, _) | (Order::Defs, _) | (Order::Field, "items") => Order::Field,
        _ => Order::Sorted,
    }
}

fn item(order: &Order) -> Order {
    match order {
        Order::Rows(fields) => Order::Row(fields.clone()),
        _ => Order::Sorted,
    }
}

fn emit_document(doc: &Map<String, Value>) -> String {
    if doc.is_empty() {
        return "{}\n".to_owned();
    }
    let fields = doc
        .get("fields")
        .and_then(Value::as_object)
        .map(field_order)
        .unwrap_or_default();
    let mut out = String::new();
    emit_map(&mut out, doc, &Order::Document(fields), 0);
    out
}

fn is_scalar(value: &Value) -> bool {
    !matches!(value, Value::Array(items) if !items.is_empty())
        && !matches!(value, Value::Object(map) if !map.is_empty())
}

fn emit_map(out: &mut String, map: &Map<String, Value>, order: &Order, indent: usize) {
    let pad = " ".repeat(indent);
    for (key, value) in ordered(map, order) {
        let key_text = emit_string(key);
        let prefix = if key_text.chars().count() > 1024 {
            format!("{pad}? {key_text}\n{pad}:")
        } else {
            format!("{pad}{key_text}:")
        };
        // A type's rules are a block list, one rule to a line.
        let rules = key == "rules" && matches!(order, Order::Document(_) | Order::Field);
        let order = child(order, key);
        match value {
            Value::Array(items) if rules && !items.is_empty() => {
                out.push_str(&prefix);
                out.push('\n');
                emit_seq(out, items, &order, indent + 2);
            }
            Value::Object(child) if !child.is_empty() => {
                out.push_str(&prefix);
                out.push('\n');
                emit_map(out, child, &order, indent + 2);
            }
            Value::Array(items) if !items.is_empty() && !items.iter().all(is_scalar) => {
                out.push_str(&prefix);
                out.push('\n');
                emit_seq(out, items, &order, indent + 2);
            }
            _ => {
                out.push_str(&prefix);
                out.push(' ');
                out.push_str(&inline(value));
                out.push('\n');
            }
        }
    }
}

fn emit_seq(out: &mut String, items: &[Value], order: &Order, indent: usize) {
    let pad = " ".repeat(indent);
    for value in items {
        match value {
            Value::Object(map) if !map.is_empty() => {
                let mut block = String::new();
                emit_map(&mut block, map, &item(order), indent + 2);
                out.push_str(&pad);
                out.push_str("- ");
                out.push_str(&block[indent + 2..]);
            }
            Value::Array(inner) if !inner.is_empty() && !inner.iter().all(is_scalar) => {
                out.push_str(&pad);
                out.push_str("-\n");
                emit_seq(out, inner, &Order::Sorted, indent + 2);
            }
            _ => {
                out.push_str(&pad);
                out.push_str("- ");
                out.push_str(&inline(value));
                out.push('\n');
            }
        }
    }
}

fn inline(value: &Value) -> String {
    match value {
        Value::String(text) => emit_string(text),
        Value::Array(items) if items.is_empty() => "[]".to_owned(),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(flow_scalar).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(_) => "{}".to_owned(),
        other => other.to_string(),
    }
}

fn flow_scalar(value: &Value) -> String {
    match value {
        Value::String(text) if text.contains([',', '[', ']', '{', '}']) => {
            serde_json::to_string(text).expect("strings serialize")
        }
        Value::Object(_) => "{}".to_owned(),
        Value::Array(_) => "[]".to_owned(),
        other => inline(other),
    }
}
