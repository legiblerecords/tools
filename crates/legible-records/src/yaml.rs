//! Restricted YAML (spec/restricted-yaml.md): a small YAML subset parsed to
//! JSON values, with the line of each value kept for error reports.

use std::collections::{BTreeMap, HashSet};

use serde_json::{Map, Number, Value};
use yaml_rust2::{
    parser::{Event, MarkedEventReceiver, Parser},
    scanner::{Marker, TScalarStyle},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YamlError {
    pub line: usize,
    pub col: usize,
    pub reason: &'static str,
    pub message: String,
}

#[derive(Default)]
struct EventSink {
    events: Vec<(Event, Marker)>,
}

impl MarkedEventReceiver for EventSink {
    fn on_event(&mut self, event: Event, marker: Marker) {
        self.events.push((event, marker));
    }
}

pub fn parse_restricted(text: &str) -> Result<Value, YamlError> {
    parse_restricted_with_lines(text).map(|(value, _)| value)
}

/// The most restricted YAML input may hold, in bytes.
pub const MAX_BYTES: usize = 65_536;

pub fn parse_restricted_with_lines(
    text: &str,
) -> Result<(Value, BTreeMap<String, usize>), YamlError> {
    parse_restricted_up_to(text, MAX_BYTES)
}

fn parse_restricted_up_to(
    text: &str,
    max_bytes: usize,
) -> Result<(Value, BTreeMap<String, usize>), YamlError> {
    if text.len() > max_bytes {
        return Err(error(
            1,
            1,
            "too_large",
            &format!("YAML input exceeds {max_bytes} bytes"),
        ));
    }

    let mut lines = BTreeMap::new();
    let mut sink = EventSink::default();
    let mut parser = Parser::new_from_str(text);
    let parse_result = parser.load(&mut sink, true);
    let document_count = sink
        .events
        .iter()
        .filter(|(event, _)| *event == Event::DocumentStart)
        .count();
    if document_count > 1 {
        let (_, marker) = sink
            .events
            .iter()
            .filter(|(event, _)| *event == Event::DocumentStart)
            .nth(1)
            .expect("document count checked");
        return Err(marked_error(
            marker,
            "multiple_documents",
            "only one YAML document is allowed",
        ));
    }

    for (event, marker) in &sink.events {
        let special = match event {
            Event::Alias(_) => Some(("alias", "YAML aliases are not allowed")),
            Event::Scalar(_, _, anchor, tag) => {
                if *anchor != 0 {
                    Some(("anchor", "YAML anchors are not allowed"))
                } else if tag.is_some() {
                    Some(("tag", "YAML tags are not allowed"))
                } else {
                    None
                }
            }
            Event::SequenceStart(anchor, tag) | Event::MappingStart(anchor, tag) => {
                if *anchor != 0 {
                    Some(("anchor", "YAML anchors are not allowed"))
                } else if tag.is_some() {
                    Some(("tag", "YAML tags are not allowed"))
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some((reason, message)) = special {
            return Err(marked_error(marker, reason, message));
        }
    }

    if let Err(parse_error) = parse_result {
        let reason = if parse_error.info() == "while parsing node, found unknown anchor" {
            "alias"
        } else {
            "syntax"
        };
        return Err(marked_error(
            parse_error.marker(),
            reason,
            parse_error.info(),
        ));
    }
    if document_count == 0 || text.trim().is_empty() {
        lines.insert(String::new(), 1);
        return Ok((Value::Null, lines));
    }

    let root_start = sink.events.iter().position(|(event, _)| {
        !matches!(
            event,
            Event::StreamStart | Event::DocumentStart | Event::StreamEnd
        )
    });
    let Some(mut cursor) = root_start else {
        lines.insert(String::new(), 1);
        return Ok((Value::Null, lines));
    };
    if matches!(sink.events[cursor].0, Event::DocumentEnd) {
        lines.insert(String::new(), sink.events[cursor].1.line());
        return Ok((Value::Null, lines));
    }
    lines.insert(String::new(), sink.events[cursor].1.line());
    if matches!(
        &sink.events[cursor].0,
        Event::Scalar(value, TScalarStyle::Plain, _, _) if value.is_empty()
    ) {
        return Ok((Value::Null, lines));
    }

    let value = parse_node(&sink.events, &mut cursor, 0, "", &mut lines)?;
    Ok((value, lines))
}

fn parse_node(
    events: &[(Event, Marker)],
    cursor: &mut usize,
    depth: usize,
    pointer: &str,
    lines: &mut BTreeMap<String, usize>,
) -> Result<Value, YamlError> {
    let Some((event, marker)) = events.get(*cursor) else {
        return Err(error(1, 1, "syntax", "unexpected end of YAML events"));
    };
    match event {
        Event::Scalar(value, style, _, _) => {
            *cursor += 1;
            scalar_value(value, *style, marker)
        }
        Event::SequenceStart(_, _) => {
            let next_depth = depth + 1;
            if next_depth > 32 {
                return Err(marked_error(
                    marker,
                    "too_deep",
                    "YAML nesting exceeds 32 collections",
                ));
            }
            *cursor += 1;
            let mut values = Vec::new();
            while !matches!(
                events.get(*cursor).map(|entry| &entry.0),
                Some(Event::SequenceEnd)
            ) {
                let item_pointer = child_pointer(pointer, &values.len().to_string());
                let item_line = events
                    .get(*cursor)
                    .map(|(_, marker)| marker.line())
                    .unwrap_or(marker.line());
                lines.insert(item_pointer.clone(), item_line);
                values.push(parse_node(
                    events,
                    cursor,
                    next_depth,
                    &item_pointer,
                    lines,
                )?);
            }
            *cursor += 1;
            Ok(Value::Array(values))
        }
        Event::MappingStart(_, _) => {
            let next_depth = depth + 1;
            if next_depth > 32 {
                return Err(marked_error(
                    marker,
                    "too_deep",
                    "YAML nesting exceeds 32 collections",
                ));
            }
            *cursor += 1;
            let mut object = Map::new();
            let mut keys = HashSet::new();
            while !matches!(
                events.get(*cursor).map(|entry| &entry.0),
                Some(Event::MappingEnd)
            ) {
                let Some((key_event, key_marker)) = events.get(*cursor) else {
                    return Err(error(1, 1, "syntax", "unterminated YAML mapping"));
                };
                let Event::Scalar(key, style, _, _) = key_event else {
                    return Err(marked_error(
                        key_marker,
                        "non_string_key",
                        "mapping keys must be scalar strings",
                    ));
                };
                if scalar_key_is_non_string(key, *style) {
                    return Err(marked_error(
                        key_marker,
                        "non_string_key",
                        "mapping keys must be strings",
                    ));
                }
                let key = key.clone();
                *cursor += 1;
                if !keys.insert(key.clone()) {
                    return Err(marked_error(
                        key_marker,
                        "duplicate_key",
                        "mapping contains a duplicate key",
                    ));
                }
                let key_pointer = child_pointer(pointer, &key);
                lines.insert(key_pointer.clone(), key_marker.line());
                let value = parse_node(events, cursor, next_depth, &key_pointer, lines)?;
                object.insert(key, value);
            }
            *cursor += 1;
            Ok(Value::Object(object))
        }
        _ => Err(marked_error(marker, "syntax", "unexpected YAML event")),
    }
}

fn child_pointer(pointer: &str, key: &str) -> String {
    let escaped = key.replace('~', "~0").replace('/', "~1");
    format!("{pointer}/{escaped}")
}

/// The output parses back to the same value when it fits within the 64 KiB input limit.
pub fn emit(value: &Value) -> String {
    emit_node(value, 0)
}

fn emit_node(value: &Value, indent: usize) -> String {
    let pad = " ".repeat(indent);
    match value {
        Value::Object(object) if object.is_empty() => format!("{pad}{{}}"),
        Value::Object(object) => object
            .iter()
            .map(|(key, value)| {
                let key = emit_string(key);
                let long_key = key.chars().count() > 1024;
                let key_prefix = if long_key {
                    format!("{pad}? {key}\n{pad}:")
                } else {
                    format!("{pad}{key}:")
                };
                match value {
                    Value::Array(items) if !items.is_empty() => {
                        format!("{key_prefix}\n{}", emit_node(value, indent + 2))
                    }
                    Value::Object(fields) if !fields.is_empty() => {
                        format!("{key_prefix}\n{}", emit_node(value, indent + 2))
                    }
                    _ => format!("{key_prefix} {}", emit_inline(value)),
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Array(items) if items.is_empty() => format!("{pad}[]"),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Array(values) if !values.is_empty() => {
                    format!("{pad}-\n{}", emit_node(item, indent + 2))
                }
                Value::Object(fields) if !fields.is_empty() => {
                    format!("{pad}-\n{}", emit_node(item, indent + 2))
                }
                _ => format!("{pad}- {}", emit_inline(item)),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => format!("{pad}{}", emit_inline(value)),
    }
}

fn emit_inline(value: &Value) -> String {
    match value {
        Value::String(value) => emit_string(value),
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(_) | Value::Object(_) => emit_node(value, 0),
    }
}

pub(crate) fn emit_string(value: &str) -> String {
    let leading_special = value.chars().next().is_some_and(|ch| {
        matches!(
            ch,
            '-' | '?'
                | ':'
                | ','
                | '['
                | ']'
                | '{'
                | '}'
                | '#'
                | '&'
                | '*'
                | '!'
                | '|'
                | '>'
                | '\''
                | '"'
                | '%'
                | '@'
                | '`'
        )
    });
    let quote = value.is_empty()
        || matches!(value, "true" | "false" | "null")
        || is_json_number(value)
        || value.trim() != value
        || leading_special
        || value.starts_with("...")
        || value.ends_with(':')
        || value.contains(": ")
        || value.contains(" #")
        || value.chars().any(char::is_control);
    if quote {
        serde_json::to_string(value).expect("strings serialize to JSON")
    } else {
        value.to_owned()
    }
}

fn scalar_key_is_non_string(value: &str, style: TScalarStyle) -> bool {
    style == TScalarStyle::Plain
        && (matches!(value, "true" | "false" | "null") || is_json_number(value))
}

fn scalar_value(value: &str, style: TScalarStyle, marker: &Marker) -> Result<Value, YamlError> {
    if style != TScalarStyle::Plain {
        return Ok(Value::String(value.to_owned()));
    }
    match value {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        "null" => return Ok(Value::Null),
        _ => {}
    }
    if !is_json_number(value) {
        return Ok(Value::String(value.to_owned()));
    }
    if !value.contains('.') && !value.contains('e') && !value.contains('E') {
        let digits = value.strip_prefix('-').unwrap_or(value);
        if digits.len() > 16 || (digits.len() == 16 && digits > "9007199254740991") {
            return Err(marked_error(
                marker,
                "number_range",
                "integer is outside the exact JSON number range",
            ));
        }
        let integer = value.parse::<i64>().expect("safe integer range fits i64");
        return Ok(Value::Number(Number::from(integer)));
    }
    let number = value
        .parse::<f64>()
        .ok()
        .and_then(Number::from_f64)
        .ok_or_else(|| {
            marked_error(
                marker,
                "number_range",
                "number is outside the finite JSON number range",
            )
        })?;
    Ok(Value::Number(number))
}

pub(crate) fn is_json_number(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    if bytes.get(index) == Some(&b'-') {
        index += 1;
    }
    match bytes.get(index) {
        Some(b'0') => index += 1,
        Some(b'1'..=b'9') => {
            index += 1;
            while matches!(bytes.get(index), Some(b'0'..=b'9')) {
                index += 1;
            }
        }
        _ => return false,
    }
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let digits = index;
        while matches!(bytes.get(index), Some(b'0'..=b'9')) {
            index += 1;
        }
        if index == digits {
            return false;
        }
    }
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        index += 1;
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index += 1;
        }
        let digits = index;
        while matches!(bytes.get(index), Some(b'0'..=b'9')) {
            index += 1;
        }
        if index == digits {
            return false;
        }
    }
    index == bytes.len()
}

fn marked_error(marker: &Marker, reason: &'static str, message: &str) -> YamlError {
    error(marker.line(), marker.col(), reason, message)
}

fn error(line: usize, col: usize, reason: &'static str, message: &str) -> YamlError {
    YamlError {
        line,
        col,
        reason,
        message: message.to_owned(),
    }
}
