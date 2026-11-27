//! Rules between a record's fields (spec/schema-language.md § Rules).
//!
//! A rule is a string such as `one_of(at, on)`,
//! `requires(status = revoked, revoked_on)` or `unique(targets, severity)`.
//! [`parse`] reads one and runs the checks that need only its text;
//! the checks that need the schema (`no field x`, nullable fields, kinds)
//! are the short form's. [`rule_text`] gives the text that goes in
//! `x-rule`. [`message`] gives a standard shape's failure message, and
//! [`evaluate`] checks an own shape against the object it sits on.

use std::cmp::Ordering;

use ::time::{Date, Month};
use serde_json::{Number, Value};

use crate::short_form::enum_value;

/// A condition in `requires`. Field names are kept as written.
#[derive(Clone, Debug, PartialEq)]
pub enum Condition {
    /// `a`: the field is given.
    Given(String),
    /// `a = v`: the field is given and equals `v`.
    Equals(String, Value),
    /// `a in (v, w, …)`: the field is given and is one of them.
    In(String, Vec<Value>),
    /// `not <condition>`.
    Not(Box<Condition>),
    /// `any_of(a, b, …)`: at least one of the fields is given.
    AnyOf(Vec<String>),
}

/// A rule, one of the shapes. Paths are kept as written, with the spaces
/// between their tokens taken out: `statements[].estimates[].expert`,
/// `at.on`.
#[derive(Clone, Debug, PartialEq)]
pub enum Rule {
    OneOf(Vec<String>),
    AtMostOne(String, String),
    AnyOf(Vec<String>),
    Requires(Condition, Condition),
    Before(String, String),
    NotAfter(String, String),
    /// `ascending(list, key)`.
    Ascending(String, String),
    /// `unique(list, key)`.
    Unique(String, String),
    Within(String, String),
}

/// What `before`, `not_after` and `ascending` compare a value as: a number,
/// a date (`date`), or a moment (`datetime`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Number,
    Date,
    Moment,
}

const SHAPES: [&str; 9] = [
    "one_of",
    "at_most_one",
    "any_of",
    "requires",
    "before",
    "not_after",
    "ascending",
    "unique",
    "within",
];

/// How deep calls and `not`s may nest, as type expressions may.
const MAX_DEPTH: usize = 32;

const BAD_RULE: &str = "bad rule";

/// A rule's text, as `x-rule` holds it: the rule as written, with each run
/// of whitespace outside double-quoted values replaced by one space and the
/// ends trimmed. Inside double quotes, where `\` escapes the next
/// character, the text is kept as written. Two rules on one object are the
/// same rule when their texts are equal.
pub fn rule_text(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut quoted = false;
    let mut escaped = false;
    let mut space = false;
    for ch in source.chars() {
        if quoted {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch.is_whitespace() {
            space = true;
        } else {
            if space && !out.is_empty() {
                out.push(' ');
            }
            space = false;
            quoted = ch == '"';
            out.push(ch);
        }
    }
    out
}

/// Parses a rule and runs the three checks after parsing, in order: the
/// call's name is a shape, the shape has the arguments it takes, and a call
/// inside `requires` is `any_of` with two or more fields. The error is the
/// problem's message, without the `` in `<rule>` `` the caller appends:
/// `bad rule`, `unknown shape frob`, `at_most_one takes two fields`,
/// `requires takes only any_of inside it`.
pub fn parse(text: &str) -> Result<Rule, String> {
    let (name, args) = Parser::new(text)
        .rule()
        .ok_or_else(|| BAD_RULE.to_owned())?;
    if !SHAPES.contains(&name.as_str()) {
        return Err(format!("unknown shape {name}"));
    }
    let takes = |what: &str| format!("{name} takes {what}");
    let pair = |args: &[Arg], first: fn(&Path) -> bool, second: fn(&Path) -> bool| match args {
        [Arg::Path(a), Arg::Path(b)] if first(a) && second(b) => Some((a.text(), b.text())),
        _ => None,
    };
    match name.as_str() {
        "one_of" | "any_of" => {
            let fields = two_or_more_fields(&args).ok_or_else(|| takes("two or more fields"))?;
            Ok(if name == "one_of" {
                Rule::OneOf(fields)
            } else {
                Rule::AnyOf(fields)
            })
        }
        "at_most_one" | "before" | "not_after" => {
            let (a, b) =
                pair(&args, Path::is_field, Path::is_field).ok_or_else(|| takes("two fields"))?;
            Ok(match name.as_str() {
                "at_most_one" => Rule::AtMostOne(a, b),
                "before" => Rule::Before(a, b),
                _ => Rule::NotAfter(a, b),
            })
        }
        "ascending" | "unique" => {
            let (list, key) = pair(&args, Path::is_field, Path::is_key)
                .ok_or_else(|| takes("a field and a key"))?;
            Ok(if name == "ascending" {
                Rule::Ascending(list, key)
            } else {
                Rule::Unique(list, key)
            })
        }
        "within" => {
            let (a, b) = pair(&args, |_| true, |_| true).ok_or_else(|| takes("two paths"))?;
            Ok(Rule::Within(a, b))
        }
        _ => {
            let [when, then] = args.as_slice() else {
                return Err(takes("two conditions"));
            };
            if !when.is_condition() || !then.is_condition() {
                return Err(takes("two conditions"));
            }
            Ok(Rule::Requires(condition(when)?, condition(then)?))
        }
    }
}

/// A condition from an argument that [`Arg::is_condition`] accepted,
/// running the third check on its calls.
fn condition(arg: &Arg) -> Result<Condition, String> {
    Ok(match arg {
        Arg::Path(path) => Condition::Given(path.text()),
        Arg::Equals(path, value) => Condition::Equals(path.text(), value.clone()),
        Arg::In(path, values) => Condition::In(path.text(), values.clone()),
        Arg::Not(inner) => Condition::Not(Box::new(condition(inner)?)),
        Arg::Call(name, args) => {
            if name != "any_of" {
                return Err("requires takes only any_of inside it".to_owned());
            }
            let fields = two_or_more_fields(args)
                .ok_or_else(|| "any_of takes two or more fields".to_owned())?;
            Condition::AnyOf(fields)
        }
    })
}

/// The arguments' names, when there are two or more and each is a field.
fn two_or_more_fields(args: &[Arg]) -> Option<Vec<String>> {
    let fields = args
        .iter()
        .map(|arg| arg.path().filter(|p| p.is_field()).map(Path::text))
        .collect::<Option<Vec<_>>>()?;
    (fields.len() >= 2).then_some(fields)
}

impl Rule {
    /// The fields of its object that the rule names, each once, in the
    /// order they first appear: the first step of each path, and for
    /// `ascending` and `unique`, the list only (the key is a field of its
    /// items). These are what `no field <name>` checks first.
    pub fn fields(&self) -> Vec<&str> {
        let mut paths: Vec<&str> = Vec::new();
        match self {
            Rule::OneOf(fields) | Rule::AnyOf(fields) => {
                paths.extend(fields.iter().map(String::as_str))
            }
            Rule::AtMostOne(a, b)
            | Rule::Before(a, b)
            | Rule::NotAfter(a, b)
            | Rule::Within(a, b) => paths.extend([a.as_str(), b.as_str()]),
            Rule::Ascending(list, _) | Rule::Unique(list, _) => paths.push(list),
            Rule::Requires(when, then) => {
                condition_fields(when, &mut paths);
                condition_fields(then, &mut paths);
            }
        }
        let mut out: Vec<&str> = Vec::new();
        for path in paths {
            let first = path.split(['.', '[']).next().unwrap_or(path);
            if !out.contains(&first) {
                out.push(first);
            }
        }
        out
    }

    /// Whether the rule has a standard shape, one that expands to JSON
    /// Schema keywords: `one_of`, `at_most_one`, `any_of` or `requires`.
    pub fn is_standard(&self) -> bool {
        matches!(
            self,
            Rule::OneOf(_) | Rule::AtMostOne(..) | Rule::AnyOf(_) | Rule::Requires(..)
        )
    }
}

fn condition_fields<'a>(condition: &'a Condition, out: &mut Vec<&'a str>) {
    match condition {
        Condition::Given(a) | Condition::Equals(a, _) | Condition::In(a, _) => out.push(a),
        Condition::Not(inner) => condition_fields(inner, out),
        Condition::AnyOf(fields) => out.extend(fields.iter().map(String::as_str)),
    }
}

/// The message a failure of the rule gives (vectors/rules.json):
/// `needs exactly one of at and on`, `at and on both given`,
/// `needs subjects, subject_refs or scope`, `revoked needs revoked_on`,
/// `revoked_on only when revoked`. A `requires` reads `<when> needs <then>`,
/// or `<when> only when <then>` when `<then>` is `a = v` or `a in (…)` and
/// `<when>` isn't.
///
/// An own shape's message names the values that broke it, so [`evaluate`]
/// gives it; here an own shape gives the same words without the values.
pub fn message(rule: &Rule) -> String {
    match rule {
        Rule::OneOf(fields) => format!("needs exactly one of {}", listed(fields, "and")),
        Rule::AtMostOne(a, b) => format!("{a} and {b} both given"),
        Rule::AnyOf(fields) => format!("needs {}", listed(fields, "or")),
        Rule::Requires(when, then) => {
            let is_value = |c: &Condition| matches!(c, Condition::Equals(..) | Condition::In(..));
            let verb = if is_value(then) && !is_value(when) {
                "only when"
            } else {
                "needs"
            };
            format!("{} {verb} {}", phrase(when), phrase(then))
        }
        Rule::Before(a, b) => format!("{a} isn't before {b}"),
        Rule::NotAfter(a, b) => format!("{a} is after {b}"),
        Rule::Ascending(list, key) => format!("{list} isn't in order of {key}"),
        Rule::Unique(list, key) => format!("more than one item in {list} has the same {key}"),
        Rule::Within(a, b) => format!("a value at {a} isn't among {b}"),
    }
}

/// A condition in words: `a`, `v`, `v or w`, `not …`, `a or b`.
fn phrase(condition: &Condition) -> String {
    match condition {
        Condition::Given(a) => a.clone(),
        Condition::Equals(_, value) => shown(value),
        Condition::In(_, values) => listed(&values.iter().map(shown).collect::<Vec<_>>(), "or"),
        Condition::Not(inner) => format!("not {}", phrase(inner)),
        Condition::AnyOf(fields) => listed(fields, "or"),
    }
}

/// `a`, `a <two> b`, or `a, b or c`.
fn listed(items: &[String], two: &str) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} {two} {b}"),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
    }
}

/// A value as a message shows it: a string as it is, anything else as JSON.
fn shown(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Checks an own shape against `object`, the object the rule sits on, and
/// gives a message for each way it breaks; none when it holds. `unique` and
/// `within` break once for each value at fault, in the order the values
/// first appear; the other shapes at most once. A standard shape gives
/// nothing: its keywords check it.
///
/// `kind` gives the kind of a field, or of a key of a list's items, by the
/// path as the rule writes it. A compared value whose kind is `None`, that
/// doesn't parse as its kind, or whose kind differs from the other side's,
/// breaks the rule. A value that isn't where the rule looks, such as a list
/// that isn't a list, is left to the type's own keywords.
pub fn evaluate(rule: &Rule, object: &Value, kind: impl Fn(&str) -> Option<Kind>) -> Vec<String> {
    match rule {
        Rule::Before(a, b) | Rule::NotAfter(a, b) => {
            let (Some(va), Some(vb)) = (object.get(a), object.get(b)) else {
                return Vec::new();
            };
            let order = match (kind(a), kind(b)) {
                (Some(ka), Some(kb)) if ka == kb => point(ka, va)
                    .zip(point(ka, vb))
                    .and_then(|(pa, pb)| pa.compare(&pb)),
                _ => None,
            };
            let holds = match rule {
                Rule::Before(..) => order == Some(Ordering::Less),
                _ => matches!(order, Some(Ordering::Less | Ordering::Equal)),
            };
            if holds {
                return Vec::new();
            }
            let (va, vb) = (shown(va), shown(vb));
            vec![match rule {
                Rule::Before(..) => format!("{a} {va} isn't before {b} {vb}"),
                _ => format!("{a} {va} is after {b} {vb}"),
            }]
        }
        Rule::Ascending(list, key) => {
            let Some(items) = object.get(list).and_then(Value::as_array) else {
                return Vec::new();
            };
            let in_order = || -> Option<()> {
                let mut last: Option<Point> = None;
                for item in items {
                    let here = point(kind(key)?, at_key(item, key)?)?;
                    if let Some(last) = &last {
                        if last.compare(&here)? != Ordering::Less {
                            return None;
                        }
                    }
                    last = Some(here);
                }
                Some(())
            };
            match in_order() {
                Some(()) => Vec::new(),
                None => vec![format!("{list} isn't in order of {key}")],
            }
        }
        Rule::Unique(list, key) => {
            let Some(items) = object.get(list).and_then(Value::as_array) else {
                return Vec::new();
            };
            let mut seen: Vec<(&Value, usize)> = Vec::new();
            for value in items.iter().filter_map(|item| at_key(item, key)) {
                match seen.iter_mut().find(|(v, _)| same(v, value)) {
                    Some((_, count)) => *count += 1,
                    None => seen.push((value, 1)),
                }
            }
            seen.into_iter()
                .filter(|(_, count)| *count > 1)
                .map(|(value, _)| {
                    format!("more than one item in {list} has {key} {}", shown(value))
                })
                .collect()
        }
        Rule::Within(path, among) => {
            let allowed = at_path(object, among);
            let mut missing: Vec<&Value> = Vec::new();
            for value in at_path(object, path) {
                if !allowed.iter().any(|a| same(a, value))
                    && !missing.iter().any(|m| same(m, value))
                {
                    missing.push(value);
                }
            }
            missing
                .into_iter()
                .map(|value| format!("{} at {path} isn't among {among}", shown(value)))
                .collect()
        }
        Rule::OneOf(_) | Rule::AtMostOne(..) | Rule::AnyOf(_) | Rule::Requires(..) => Vec::new(),
    }
}

/// The value at a key (`a` or `a.b`) of an item, if there is one.
fn at_key<'a>(item: &'a Value, key: &str) -> Option<&'a Value> {
    key.split('.').try_fold(item, |value, step| value.get(step))
}

/// Every value at a path from `object`, in document order, stepping into a
/// list's items at `[]`. Steps that find nothing, or a `[]` on something
/// that isn't a list, contribute nothing.
fn at_path<'a>(object: &'a Value, path: &str) -> Vec<&'a Value> {
    let mut values = vec![object];
    for step in path.split('.') {
        let (name, list) = match step.strip_suffix("[]") {
            Some(name) => (name, true),
            None => (step, false),
        };
        let mut next = Vec::new();
        for value in values {
            match value.get(name) {
                Some(Value::Array(items)) if list => next.extend(items),
                Some(_) if list => {}
                Some(found) => next.push(found),
                None => {}
            }
        }
        values = next;
    }
    values
}

/// Whether two values are the same, with numbers compared as numbers
/// (`1` and `1.0` are the same), as JSON Schema's `uniqueItems` compares.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => compare_numbers(x, y) == Some(Ordering::Equal),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same(x, y))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

/// A value read as its kind.
enum Point {
    Number(Number),
    Date(Date),
    Moment(crate::time::Instant),
}

impl Point {
    fn compare(&self, other: &Point) -> Option<Ordering> {
        match (self, other) {
            (Point::Number(a), Point::Number(b)) => compare_numbers(a, b),
            (Point::Date(a), Point::Date(b)) => Some(a.cmp(b)),
            (Point::Moment(a), Point::Moment(b)) => Some(a.cmp(b)),
            _ => None,
        }
    }
}

/// Reads a value as `kind`, or `None` when it doesn't parse as one.
fn point(kind: Kind, value: &Value) -> Option<Point> {
    match kind {
        Kind::Number => value.as_number().cloned().map(Point::Number),
        Kind::Date => value.as_str().and_then(full_date).map(Point::Date),
        Kind::Moment => value
            .as_str()
            .and_then(|s| crate::time::parse(s).ok())
            .map(Point::Moment),
    }
}

/// An RFC 3339 `full-date`, `YYYY-MM-DD`, as JSON Schema's `date` format
/// has it.
fn full_date(text: &str) -> Option<Date> {
    let bytes = text.as_bytes();
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = bytes.get(range)?;
        part.iter().all(u8::is_ascii_digit).then(|| {
            part.iter()
                .fold(0, |n, digit| n * 10 + u32::from(digit - b'0'))
        })
    };
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year = i32::try_from(digits(0..4)?).ok()?;
    let month = Month::try_from(u8::try_from(digits(5..7)?).ok()?).ok()?;
    let day = u8::try_from(digits(8..10)?).ok()?;
    Date::from_calendar_date(year, month, day).ok()
}

/// Compares two JSON numbers as numbers: integers exactly, anything else as
/// floating point.
fn compare_numbers(a: &Number, b: &Number) -> Option<Ordering> {
    let integer = |n: &Number| {
        n.as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from))
    };
    match (integer(a), integer(b)) {
        (Some(a), Some(b)) => Some(a.cmp(&b)),
        _ => a.as_f64()?.partial_cmp(&b.as_f64()?),
    }
}

// ---------- Parsing ----------

/// An argument as the grammar reads it, before the checks.
enum Arg {
    Not(Box<Arg>),
    Equals(Path, Value),
    In(Path, Vec<Value>),
    Call(String, Vec<Arg>),
    Path(Path),
}

impl Arg {
    fn path(&self) -> Option<&Path> {
        match self {
            Arg::Path(path) => Some(path),
            _ => None,
        }
    }

    /// A field, `a = v` or `a in (…)` with `a` a field, `not` and a
    /// condition, or a call.
    fn is_condition(&self) -> bool {
        match self {
            Arg::Path(path) | Arg::Equals(path, _) | Arg::In(path, _) => path.is_field(),
            Arg::Not(inner) => inner.is_condition(),
            Arg::Call(..) => true,
        }
    }
}

/// A path's steps, each a name and whether it steps into a list (`[]`).
struct Path(Vec<(String, bool)>);

impl Path {
    /// One step without `[]`.
    fn is_field(&self) -> bool {
        matches!(self.0.as_slice(), [(_, false)])
    }

    /// No step with `[]`.
    fn is_key(&self) -> bool {
        self.0.iter().all(|(_, list)| !list)
    }

    fn text(&self) -> String {
        self.0
            .iter()
            .map(|(name, list)| {
                if *list {
                    format!("{name}[]")
                } else {
                    name.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(".")
    }
}

/// A hand parser over the grammar in § Rules. Each method gives `None` when
/// the text doesn't fit, and may leave the position anywhere then.
struct Parser {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn new(text: &str) -> Parser {
        Parser {
            chars: text.chars().collect(),
            pos: 0,
            depth: 0,
        }
    }

    /// `rule = call`, with spaces allowed around it.
    fn rule(&mut self) -> Option<(String, Vec<Arg>)> {
        self.spaces();
        let name = self.name()?;
        let Arg::Call(name, args) = self.call(name)? else {
            return None;
        };
        self.spaces();
        (self.pos == self.chars.len()).then_some((name, args))
    }

    /// The rest of a call after its name: `(` straight after it, then its
    /// arguments.
    fn call(&mut self, name: String) -> Option<Arg> {
        if !self.eat('(') {
            return None;
        }
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return None;
        }
        let mut args = Vec::new();
        loop {
            args.push(self.arg()?);
            self.spaces();
            if self.eat(')') {
                break;
            }
            if !self.eat(',') {
                return None;
            }
        }
        self.depth -= 1;
        Some(Arg::Call(name, args))
    }

    /// `arg = "not" arg | path "=" value | path "in" "(" value ("," value)* ")" | call | path`
    fn arg(&mut self) -> Option<Arg> {
        self.spaces();
        let (start, depth) = (self.pos, self.depth);
        // `not` is a keyword when a space and an argument follow it, and a
        // name otherwise (`one_of(not, b)`, `requires(not = x, b)`).
        if self.keyword("not") {
            self.depth += 1;
            if self.depth <= MAX_DEPTH {
                if let Some(inner) = self.arg() {
                    if self.at_arg_end() {
                        self.depth -= 1;
                        return Some(Arg::Not(Box::new(inner)));
                    }
                }
            }
            self.depth = depth;
            self.pos = start;
        }
        let name = self.name()?;
        if self.peek() == Some('(') {
            return self.call(name);
        }
        let mut steps = vec![(name, self.list_step())];
        loop {
            let before = self.pos;
            self.spaces();
            if !self.eat('.') {
                self.pos = before;
                break;
            }
            self.spaces();
            let name = self.name()?;
            steps.push((name, self.list_step()));
        }
        let path = Path(steps);
        let before = self.pos;
        self.spaces();
        if self.eat('=') {
            return Some(Arg::Equals(path, self.value()?));
        }
        if self.keyword("in") {
            if !self.eat('(') {
                return None;
            }
            let mut values = vec![self.value()?];
            while self.eat(',') {
                values.push(self.value()?);
            }
            return self.eat(')').then_some(Arg::In(path, values));
        }
        self.pos = before;
        Some(Arg::Path(path))
    }

    /// A value, read as `enum`'s values are, ending at a `,` or `)` outside
    /// double quotes. The `,` or `)` is left for the caller.
    fn value(&mut self) -> Option<Value> {
        let start = self.pos;
        let mut quoted = false;
        while let Some(ch) = self.peek() {
            if quoted {
                if ch == '\\' {
                    self.pos += 1;
                } else if ch == '"' {
                    quoted = false;
                }
            } else if ch == '"' {
                quoted = true;
            } else if ch == ',' || ch == ')' {
                let text: String = self.chars[start..self.pos].iter().collect();
                let text = text.trim();
                return if text.is_empty() {
                    None
                } else {
                    enum_value(text).ok()
                };
            }
            self.pos += 1;
        }
        None
    }

    /// `name = [A-Za-z_][A-Za-z0-9_-]*`
    fn name(&mut self) -> Option<String> {
        let start = self.pos;
        if !self
            .peek()
            .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        {
            return None;
        }
        while self
            .peek()
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        {
            self.pos += 1;
        }
        Some(self.chars[start..self.pos].iter().collect())
    }

    /// `[]` straight after a step's name.
    fn list_step(&mut self) -> bool {
        if self.chars.get(self.pos..self.pos + 2) == Some(&['[', ']']) {
            self.pos += 2;
            true
        } else {
            false
        }
    }

    /// The word `word` followed by a space, which is consumed with it.
    /// Otherwise nothing is consumed.
    fn keyword(&mut self, word: &str) -> bool {
        let start = self.pos;
        if self.name().as_deref() == Some(word) && self.spaces() {
            return true;
        }
        self.pos = start;
        false
    }

    /// Whether a `,` or `)` comes next, after any spaces. Consumes nothing.
    fn at_arg_end(&self) -> bool {
        self.chars[self.pos..]
            .iter()
            .find(|ch| !ch.is_whitespace())
            .is_some_and(|ch| matches!(ch, ',' | ')'))
    }

    /// Skips whitespace, and says whether there was any.
    fn spaces(&mut self) -> bool {
        let start = self.pos;
        while self.peek().is_some_and(char::is_whitespace) {
            self.pos += 1;
        }
        self.pos > start
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn eat(&mut self, ch: char) -> bool {
        if self.peek() == Some(ch) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn field(name: &str) -> String {
        name.to_owned()
    }

    fn given(name: &str) -> Condition {
        Condition::Given(field(name))
    }

    #[test]
    fn parse_every_shape() {
        let cases: Vec<(&str, Rule)> = vec![
            (
                "one_of(at, on)",
                Rule::OneOf(vec![field("at"), field("on")]),
            ),
            (
                "one_of(email, phone, post)",
                Rule::OneOf(vec![field("email"), field("phone"), field("post")]),
            ),
            (
                "at_most_one(requested_at, requested_on)",
                Rule::AtMostOne(field("requested_at"), field("requested_on")),
            ),
            (
                "any_of(subjects, subject_refs, scope)",
                Rule::AnyOf(vec![
                    field("subjects"),
                    field("subject_refs"),
                    field("scope"),
                ]),
            ),
            (
                "requires(line, affected_file)",
                Rule::Requires(given("line"), given("affected_file")),
            ),
            (
                "requires(status = revoked, revoked_on)",
                Rule::Requires(
                    Condition::Equals(field("status"), json!("revoked")),
                    given("revoked_on"),
                ),
            ),
            (
                "requires(kind in (service, shared), owner)",
                Rule::Requires(
                    Condition::In(field("kind"), vec![json!("service"), json!("shared")]),
                    given("owner"),
                ),
            ),
            (
                "requires(not kind = service, contact)",
                Rule::Requires(
                    Condition::Not(Box::new(Condition::Equals(field("kind"), json!("service")))),
                    given("contact"),
                ),
            ),
            (
                "requires(status = fixed, any_of(fixed_at, fixed_on))",
                Rule::Requires(
                    Condition::Equals(field("status"), json!("fixed")),
                    Condition::AnyOf(vec![field("fixed_at"), field("fixed_on")]),
                ),
            ),
            (
                "requires(not kind in (service, shared), any_of(person, person_match))",
                Rule::Requires(
                    Condition::Not(Box::new(Condition::In(
                        field("kind"),
                        vec![json!("service"), json!("shared")],
                    ))),
                    Condition::AnyOf(vec![field("person"), field("person_match")]),
                ),
            ),
            (
                "before(original_due, expires)",
                Rule::Before(field("original_due"), field("expires")),
            ),
            (
                "not_after(starts_on, ends_on)",
                Rule::NotAfter(field("starts_on"), field("ends_on")),
            ),
            (
                "ascending(history, since)",
                Rule::Ascending(field("history"), field("since")),
            ),
            (
                "ascending(points, at.moment)",
                Rule::Ascending(field("points"), field("at.moment")),
            ),
            (
                "unique(experts, id)",
                Rule::Unique(field("experts"), field("id")),
            ),
            (
                "within(statements[].estimates[].expert, experts[].id)",
                Rule::Within(
                    field("statements[].estimates[].expert"),
                    field("experts[].id"),
                ),
            ),
            // Values are read as enum's values are.
            (
                "requires(a = \"x y\", b)",
                Rule::Requires(Condition::Equals(field("a"), json!("x y")), given("b")),
            ),
            (
                "requires(a = 3, b)",
                Rule::Requires(Condition::Equals(field("a"), json!(3)), given("b")),
            ),
            (
                "requires(a = two words , b)",
                Rule::Requires(
                    Condition::Equals(field("a"), json!("two words")),
                    given("b"),
                ),
            ),
            (
                "requires(a in (\"x, y\", 2.5, \"(z)\"), b)",
                Rule::Requires(
                    Condition::In(field("a"), vec![json!("x, y"), json!(2.5), json!("(z)")]),
                    given("b"),
                ),
            ),
            // Spaces may separate tokens, newlines included.
            (
                "one_of( at ,on )",
                Rule::OneOf(vec![field("at"), field("on")]),
            ),
            ("one_of(a,\n  b)", Rule::OneOf(vec![field("a"), field("b")])),
            ("  one_of(a,b)  ", Rule::OneOf(vec![field("a"), field("b")])),
            (
                "requires(a=v,b)",
                Rule::Requires(Condition::Equals(field("a"), json!("v")), given("b")),
            ),
            (
                "within(a . b[], c[] . d)",
                Rule::Within(field("a.b[]"), field("c[].d")),
            ),
            // `not` and `in` are names when they aren't keywords.
            (
                "one_of(not, in)",
                Rule::OneOf(vec![field("not"), field("in")]),
            ),
            (
                "requires(not = x, in)",
                Rule::Requires(Condition::Equals(field("not"), json!("x")), given("in")),
            ),
            (
                "requires(not not a, b)",
                Rule::Requires(
                    Condition::Not(Box::new(Condition::Not(Box::new(given("a"))))),
                    given("b"),
                ),
            ),
            (
                "requires(not in (a), b)",
                Rule::Requires(Condition::In(field("not"), vec![json!("a")]), given("b")),
            ),
            (
                "requires(nota, b)",
                Rule::Requires(given("nota"), given("b")),
            ),
            (
                "one_of(a-b, _c)",
                Rule::OneOf(vec![field("a-b"), field("_c")]),
            ),
        ];
        for (text, rule) in cases {
            assert_eq!(parse(text), Ok(rule), "{text}");
        }
    }

    #[test]
    fn rule_text_collapses_whitespace() {
        assert_eq!(rule_text("one_of( at ,on )"), "one_of( at ,on )");
        assert_eq!(rule_text("one_of(a,\n  b)"), "one_of(a, b)");
        assert_eq!(rule_text("one_of(a,b)"), "one_of(a,b)");
        assert_eq!(
            rule_text("  requires(kind in (service, shared),  owner)\t"),
            "requires(kind in (service, shared), owner)"
        );
    }

    /// Whitespace inside a double-quoted value is kept as written, so the
    /// text and the value it expands to agree.
    #[test]
    fn rule_text_keeps_whitespace_inside_double_quotes() {
        assert_eq!(
            rule_text(r#"requires(a = "x  y",  b)"#),
            r#"requires(a = "x  y", b)"#
        );
        assert_eq!(
            rule_text("requires(a in (\"p\\\"  q\",\n  \" r \"),  b)"),
            "requires(a in (\"p\\\"  q\", \" r \"), b)"
        );
        assert_eq!(rule_text("one_of(a,\n  b)"), "one_of(a, b)");
        let text = rule_text(r#"requires(a = "x  y",  b)"#);
        assert_eq!(parse(&text), parse(r#"requires(a = "x  y", b)"#));
        assert_eq!(
            parse(&text),
            Ok(Rule::Requires(
                Condition::Equals("a".to_owned(), Value::from("x  y")),
                Condition::Given("b".to_owned()),
            ))
        );
    }

    #[test]
    fn parse_errors() {
        let cases = [
            // The grammar.
            ("one_of(a, b", "bad rule"),
            ("one_of(a, b))", "bad rule"),
            ("one_of a, b)", "bad rule"),
            ("one_of (a, b)", "bad rule"),
            ("one_of()", "bad rule"),
            ("one_of(a, , b)", "bad rule"),
            ("one_of(a, b,)", "bad rule"),
            ("", "bad rule"),
            ("a", "bad rule"),
            ("1x(a, b)", "bad rule"),
            ("within(a [], b)", "bad rule"),
            ("within(a[ ], b)", "bad rule"),
            ("within(a., b)", "bad rule"),
            ("requires(a =, b)", "bad rule"),
            ("requires(a in (), b)", "bad rule"),
            ("requires(a in(x), b)", "bad rule"),
            ("requires(a in (x,), b)", "bad rule"),
            ("requires(a = \"x\" y, b)", "bad rule"),
            ("requires(a = 'x', b)", "bad rule"),
            ("requires(a = null, b)", "bad rule"),
            ("requires(a = \"x, b)", "bad rule"),
            // Check 1: the call's name is a shape.
            ("frob(a, b)", "unknown shape frob"),
            ("not(a, b)", "unknown shape not"),
            // Check 2: the shape has the arguments it takes.
            ("at_most_one(a, b, c)", "at_most_one takes two fields"),
            ("at_most_one(a)", "at_most_one takes two fields"),
            ("one_of(a)", "one_of takes two or more fields"),
            ("one_of(a, b = c)", "one_of takes two or more fields"),
            ("one_of(a, b.c)", "one_of takes two or more fields"),
            ("any_of(a, b[])", "any_of takes two or more fields"),
            ("any_of(a, any_of(b, c))", "any_of takes two or more fields"),
            ("before(a, b, c)", "before takes two fields"),
            ("not_after(a.b, c)", "not_after takes two fields"),
            ("requires(a)", "requires takes two conditions"),
            ("requires(a, b, c)", "requires takes two conditions"),
            ("requires(a.b, c)", "requires takes two conditions"),
            ("requires(a[] = x, c)", "requires takes two conditions"),
            (
                "requires(not a.b in (x), c)",
                "requires takes two conditions",
            ),
            ("ascending(a.b, c)", "ascending takes a field and a key"),
            ("ascending(a, c[])", "ascending takes a field and a key"),
            ("unique(a)", "unique takes a field and a key"),
            ("within(a, b = c)", "within takes two paths"),
            ("within(a)", "within takes two paths"),
            // Check 3: a call inside requires is any_of, with two or more fields.
            (
                "requires(one_of(a, b), c)",
                "requires takes only any_of inside it",
            ),
            (
                "requires(a, not frob(b, c))",
                "requires takes only any_of inside it",
            ),
            ("requires(any_of(a), c)", "any_of takes two or more fields"),
            (
                "requires(any_of(a, b.c), c)",
                "any_of takes two or more fields",
            ),
            // The checks run in order: the shape before its arguments.
            ("frob(a)", "unknown shape frob"),
            ("requires(one_of(a, b))", "requires takes two conditions"),
        ];
        for (text, message) in cases {
            assert_eq!(parse(text), Err(message.to_owned()), "{text}");
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let nested = |n: usize| format!("requires({}a, b)", "not ".repeat(n));
        assert!(parse(&nested(30)).is_ok());
        assert_eq!(parse(&nested(40)), Err("bad rule".to_owned()));
        assert_eq!(parse(&nested(100_000)), Err("bad rule".to_owned()));
        let calls = format!("{}a{}", "f(".repeat(100_000), ")".repeat(100_000));
        assert_eq!(parse(&calls), Err("bad rule".to_owned()));
    }

    #[test]
    fn fields_are_the_object_fields_a_rule_names() {
        let fields = |text: &str| -> Vec<String> {
            parse(text)
                .unwrap()
                .fields()
                .into_iter()
                .map(str::to_owned)
                .collect()
        };
        assert_eq!(fields("one_of(at, on)"), ["at", "on"]);
        assert_eq!(
            fields("requires(not kind in (a, b), any_of(person, person_match))"),
            ["kind", "person", "person_match"]
        );
        assert_eq!(fields("ascending(history, since)"), ["history"]);
        assert_eq!(fields("unique(experts, id)"), ["experts"]);
        assert_eq!(
            fields("within(statements[].estimates[].expert, experts[].id)"),
            ["statements", "experts"]
        );
        assert_eq!(fields("within(groups[].parent, groups[].id)"), ["groups"]);
    }

    #[test]
    fn standard_shapes() {
        for text in [
            "one_of(a, b)",
            "at_most_one(a, b)",
            "any_of(a, b)",
            "requires(a, b)",
        ] {
            assert!(parse(text).unwrap().is_standard(), "{text}");
        }
        for text in [
            "before(a, b)",
            "not_after(a, b)",
            "ascending(a, b)",
            "unique(a, b)",
            "within(a, b)",
        ] {
            assert!(!parse(text).unwrap().is_standard(), "{text}");
        }
    }

    #[test]
    fn standard_messages() {
        // From vectors/rules.json.
        let cases = [
            ("one_of(at, on)", "needs exactly one of at and on"),
            (
                "one_of(email, phone, post)",
                "needs exactly one of email, phone or post",
            ),
            (
                "at_most_one(requested_at, requested_on)",
                "requested_at and requested_on both given",
            ),
            (
                "any_of(subjects, subject_refs, scope)",
                "needs subjects, subject_refs or scope",
            ),
            ("any_of(digest, tag)", "needs digest or tag"),
            ("requires(line, affected_file)", "line needs affected_file"),
            (
                "requires(status = revoked, revoked_on)",
                "revoked needs revoked_on",
            ),
            (
                "requires(revoked_on, status = revoked)",
                "revoked_on only when revoked",
            ),
            (
                "requires(kind in (service, shared), owner)",
                "service or shared needs owner",
            ),
            (
                "requires(not kind = service, contact)",
                "not service needs contact",
            ),
            (
                "requires(status = fixed, any_of(fixed_at, fixed_on))",
                "fixed needs fixed_at or fixed_on",
            ),
            (
                "requires(fixed_on, status in (fixed, closed))",
                "fixed_on only when fixed or closed",
            ),
            (
                "requires(not kind in (service, shared), any_of(person_id, person_email))",
                "not service or shared needs person_id or person_email",
            ),
            (
                "requires(status = closed, resolution in (done, dropped))",
                "closed needs done or dropped",
            ),
            ("requires(a in (x, y, z), b)", "x, y or z needs b"),
            ("requires(a = 3, b)", "3 needs b"),
        ];
        for (text, expected) in cases {
            assert_eq!(message(&parse(text).unwrap()), expected, "{text}");
        }
    }

    fn kinds(path: &str) -> Option<Kind> {
        match path {
            "low" | "high" | "revision" | "acknowledgment_from" | "loss" | "big" | "small" => {
                Some(Kind::Number)
            }
            "original_due" | "expires" | "starts_on" | "ends_on" | "on" | "at.on" => {
                Some(Kind::Date)
            }
            "opened_at" | "closed_at" | "since" => Some(Kind::Moment),
            _ => None,
        }
    }

    fn check(text: &str, record: Value) -> Vec<String> {
        evaluate(&parse(text).unwrap(), &record, kinds)
    }

    #[test]
    fn evaluate_before_and_not_after() {
        let rule = "before(original_due, expires)";
        assert_eq!(check(rule, json!({})), Vec::<String>::new());
        assert_eq!(
            check(rule, json!({"original_due": "2026-03-01"})),
            Vec::<String>::new()
        );
        assert_eq!(
            check(rule, json!({"expires": "2026-03-01"})),
            Vec::<String>::new()
        );
        assert_eq!(
            check(
                rule,
                json!({"original_due": "2026-01-31", "expires": "2026-02-01"})
            ),
            Vec::<String>::new()
        );
        assert_eq!(
            check(
                rule,
                json!({"original_due": "2026-02-01", "expires": "2026-02-01"})
            ),
            ["original_due 2026-02-01 isn't before expires 2026-02-01"]
        );
        assert_eq!(
            check(
                rule,
                json!({"original_due": "2026-03-01", "expires": "2026-02-01"})
            ),
            ["original_due 2026-03-01 isn't before expires 2026-02-01"]
        );
        // A value that doesn't parse as its kind breaks the rule (Review Focus 3).
        assert_eq!(
            check(
                rule,
                json!({"original_due": "soon", "expires": "2026-02-01"})
            ),
            ["original_due soon isn't before expires 2026-02-01"]
        );
        assert_eq!(
            check(
                rule,
                json!({"original_due": "2026-01-01", "expires": "2026-02-30"})
            ),
            ["original_due 2026-01-01 isn't before expires 2026-02-30"]
        );
        assert_eq!(
            check(
                rule,
                json!({"original_due": "2026-01-01", "expires": "2026-02-01T00:00:00Z"})
            ),
            ["original_due 2026-01-01 isn't before expires 2026-02-01T00:00:00Z"]
        );
        assert_eq!(
            check(
                rule,
                json!({"original_due": 20260101, "expires": "2026-02-01"})
            ),
            ["original_due 20260101 isn't before expires 2026-02-01"]
        );

        // Datetimes compare as moments.
        let rule = "before(opened_at, closed_at)";
        assert_eq!(
            check(
                rule,
                json!({"opened_at": "2026-01-01T10:00:00+02:00", "closed_at": "2026-01-01T09:00:00Z"})
            ),
            Vec::<String>::new()
        );
        assert_eq!(
            check(
                rule,
                json!({"opened_at": "2026-01-01T09:00:00Z", "closed_at": "2026-01-01T10:00:00+02:00"})
            ),
            ["opened_at 2026-01-01T09:00:00Z isn't before closed_at 2026-01-01T10:00:00+02:00"]
        );

        // Numbers compare as numbers.
        let rule = "before(low, high)";
        assert_eq!(
            check(rule, json!({"low": 2.5, "high": 10})),
            Vec::<String>::new()
        );
        assert_eq!(
            check(rule, json!({"low": 10, "high": 2.5})),
            ["low 10 isn't before high 2.5"]
        );
        assert_eq!(
            check(rule, json!({"low": "1", "high": 2})),
            ["low 1 isn't before high 2"]
        );
        assert_eq!(
            check(
                "before(small, big)",
                json!({"small": 9007199254740992u64, "big": 9007199254740993u64})
            ),
            Vec::<String>::new()
        );

        let rule = "not_after(acknowledgment_from, revision)";
        assert_eq!(check(rule, json!({"revision": 3})), Vec::<String>::new());
        assert_eq!(
            check(rule, json!({"acknowledgment_from": 3, "revision": 3})),
            Vec::<String>::new()
        );
        assert_eq!(
            check(rule, json!({"acknowledgment_from": 10, "revision": 9})),
            ["acknowledgment_from 10 is after revision 9"]
        );
        let rule = "not_after(starts_on, ends_on)";
        assert_eq!(
            check(
                rule,
                json!({"starts_on": "2026-03-01", "ends_on": "2026-03-01"})
            ),
            Vec::<String>::new()
        );
        assert_eq!(
            check(
                rule,
                json!({"starts_on": "2026-03-02", "ends_on": "2026-03-01"})
            ),
            ["starts_on 2026-03-02 is after ends_on 2026-03-01"]
        );

        // A field with no kind breaks the rule: Task 5 refuses such a schema.
        assert_eq!(
            check("before(x, y)", json!({"x": 1, "y": 2})),
            ["x 1 isn't before y 2"]
        );
        // So do two fields of different kinds.
        assert_eq!(
            check(
                "before(on, since)",
                json!({"on": "2026-01-01", "since": "2026-01-02T00:00:00Z"})
            ),
            ["on 2026-01-01 isn't before since 2026-01-02T00:00:00Z"]
        );
    }

    #[test]
    fn evaluate_ascending() {
        let rule = "ascending(history, since)";
        let ok = Vec::<String>::new();
        let broken = ["history isn't in order of since"];
        assert_eq!(check(rule, json!({})), ok);
        assert_eq!(check(rule, json!({"history": []})), ok);
        assert_eq!(
            check(
                rule,
                json!({"history": [{"since": "2026-01-01T08:00:00Z"}, {"since": "2026-01-01T09:00:00Z"}]})
            ),
            ok
        );
        assert_eq!(
            check(
                rule,
                json!({"history": [{"since": "2026-01-01T10:00:00+02:00"}, {"since": "2026-01-01T09:00:00Z"}]})
            ),
            ok
        );
        assert_eq!(
            check(
                rule,
                json!({"history": [{"since": "2026-01-01T09:00:00Z"}, {"since": "2026-01-01T08:00:00Z"}]})
            ),
            broken
        );
        // Equal is not ascending.
        assert_eq!(
            check(
                rule,
                json!({"history": [{"since": "2026-01-01T09:00:00Z"}, {"since": "2026-01-01T11:00:00+02:00"}]})
            ),
            broken
        );
        // An item without the key breaks it, even alone.
        assert_eq!(
            check(
                rule,
                json!({"history": [{"since": "2026-01-01T09:00:00Z"}, {"value": "high"}]})
            ),
            broken
        );
        assert_eq!(check(rule, json!({"history": [{"value": "low"}]})), broken);
        assert_eq!(check(rule, json!({"history": [3]})), broken);
        assert_eq!(
            check(rule, json!({"history": [{"since": "later"}]})),
            broken
        );

        let rule = "ascending(points, loss)";
        assert_eq!(
            check(
                rule,
                json!({"points": [{"loss": 9}, {"loss": 10}, {"loss": 10.5}]})
            ),
            ok
        );
        assert_eq!(
            check(rule, json!({"points": [{"loss": 10}, {"loss": 9}]})),
            ["points isn't in order of loss"]
        );

        // A dotted key.
        let rule = "ascending(items, at.on)";
        assert_eq!(
            check(
                rule,
                json!({"items": [{"at": {"on": "2026-01-01"}}, {"at": {"on": "2026-01-02"}}]})
            ),
            ok
        );
        assert_eq!(
            check(
                rule,
                json!({"items": [{"at": {"on": "2026-01-02"}}, {"at": {"on": "2026-01-01"}}]})
            ),
            ["items isn't in order of at.on"]
        );
        assert_eq!(
            check(
                rule,
                json!({"items": [{"at": {"on": "2026-01-02"}}, {"at": {}}]})
            ),
            ["items isn't in order of at.on"]
        );
    }

    #[test]
    fn evaluate_unique() {
        let rule = "unique(experts, id)";
        let ok = Vec::<String>::new();
        assert_eq!(check(rule, json!({})), ok);
        assert_eq!(check(rule, json!({"experts": []})), ok);
        assert_eq!(
            check(rule, json!({"experts": [{"id": "ann"}, {"id": "bob"}]})),
            ok
        );
        // Items without the key are skipped.
        assert_eq!(
            check(
                rule,
                json!({"experts": [{"id": "ann"}, {"name": "Bob"}, {"name": "Cyd"}]})
            ),
            ok
        );
        assert_eq!(
            check(
                rule,
                json!({"experts": [{"id": "ann"}, {"id": "bob"}, {"id": "ann"}]})
            ),
            ["more than one item in experts has id ann"]
        );
        // Once per value, in the order the values first appear.
        assert_eq!(
            check(
                rule,
                json!({"experts": [{"id": "bob"}, {"id": "ann"}, {"id": "ann"}, {"id": "bob"}, {"id": "ann"}]})
            ),
            [
                "more than one item in experts has id bob",
                "more than one item in experts has id ann"
            ]
        );
        assert_eq!(
            check(
                "unique(targets, severity)",
                json!({"targets": [{"severity": 1}, {"severity": 1.0}]})
            ),
            ["more than one item in targets has severity 1"]
        );
        assert_eq!(
            check(
                "unique(links, box.id)",
                json!({"links": [{"box": {"id": "a"}}, {"box": {"id": "a"}}]})
            ),
            ["more than one item in links has box.id a"]
        );
    }

    #[test]
    fn evaluate_within() {
        let rule = "within(statements[].estimates[].expert, experts[].id)";
        let ok = Vec::<String>::new();
        assert_eq!(
            check(rule, json!({"experts": [{"id": "ann"}], "statements": []})),
            ok
        );
        assert_eq!(
            check(
                rule,
                json!({"experts": [], "statements": [{"estimates": []}]})
            ),
            ok
        );
        assert_eq!(
            check(
                rule,
                json!({
                    "experts": [{"id": "ann"}, {"id": "bob"}],
                    "statements": [
                        {"estimates": [{"expert": "ann"}, {"expert": "bob"}]},
                        {"estimates": []},
                        {"estimates": [{"expert": "ann"}]}
                    ]
                })
            ),
            ok
        );
        assert_eq!(
            check(
                rule,
                json!({"experts": [], "statements": [{"estimates": [{"expert": "ann"}]}]})
            ),
            ["ann at statements[].estimates[].expert isn't among experts[].id"]
        );
        assert_eq!(
            check(
                rule,
                json!({
                    "experts": [{"id": "ann"}],
                    "statements": [
                        {"estimates": [{"expert": "dee"}, {"expert": "ann"}]},
                        {"estimates": [{"expert": "cyd"}, {"expert": "dee"}]}
                    ]
                })
            ),
            [
                "dee at statements[].estimates[].expert isn't among experts[].id",
                "cyd at statements[].estimates[].expert isn't among experts[].id"
            ]
        );
        let rule = "within(groups[].parent, groups[].id)";
        assert_eq!(
            check(
                rule,
                json!({"groups": [{"id": "top"}, {"id": "sub", "parent": "top"}]})
            ),
            ok
        );
        assert_eq!(
            check(
                rule,
                json!({"groups": [{"id": "top", "parent": "none"}, {"id": "sub", "parent": "top"}]})
            ),
            ["none at groups[].parent isn't among groups[].id"]
        );
        // Values that aren't where a path points are skipped.
        assert_eq!(
            check(
                rule,
                json!({"groups": [3, {"id": "top"}, {"parent": "top"}]})
            ),
            ok
        );
        assert_eq!(check(rule, json!({"groups": "top"})), ok);
    }

    #[test]
    fn evaluate_on_something_that_isnt_an_object() {
        // The type reports it; the rule doesn't (Review Focus 5).
        let ok = Vec::<String>::new();
        for record in [json!(3), json!(null), json!(["a"]), json!("x")] {
            assert_eq!(check("before(low, high)", record.clone()), ok);
            assert_eq!(check("ascending(points, loss)", record.clone()), ok);
            assert_eq!(check("unique(experts, id)", record.clone()), ok);
            assert_eq!(check("within(groups[].parent, groups[].id)", record), ok);
        }
    }

    #[test]
    fn evaluate_standard_shapes_is_empty() {
        // Standard shapes are checked by their keywords.
        assert_eq!(check("one_of(a, b)", json!({})), Vec::<String>::new());
        assert_eq!(
            check("requires(a, b)", json!({"a": 1})),
            Vec::<String>::new()
        );
    }
}
