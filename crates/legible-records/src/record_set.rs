//! Record sets (spec/records.md § Record sets): many records of one type in
//! one NDJSON file, `records/<kind>.ndjson`.
//!
//! [`write`] makes one; [`Reader`] checks one as a stream, yielding each
//! record as it goes and deciding at [`Reader::finish`]; [`check`] reads one
//! held in memory. Every problem names the line it is on.

use std::io::{BufRead, BufReader, Read};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The longest line the reference tools read, in bytes, `\n` included.
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// A kind with more records than this (of one version) is packed as a set.
pub const SET_THRESHOLD: usize = 1000;

/// Where a kind's record set lives in a bundle.
pub fn set_path(kind: &str) -> String {
    format!("records/{kind}.ndjson")
}

/// The kind a record set's path names, if it is `records/<kind>.ndjson`.
pub fn kind_of_path(path: &str) -> Option<&str> {
    let kind = path.strip_prefix("records/")?.strip_suffix(".ndjson")?;
    (!kind.contains('/')).then_some(kind)
}

/// A record as one record-set line: compact, keys sorted, text as UTF-8, and
/// a final `\n`.
pub fn canonical_line(record: &Value) -> Vec<u8> {
    let mut line = serde_json::to_vec(record).expect("JSON values serialize");
    line.push(b'\n');
    line
}

fn is_key(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn id_of(record: &Value) -> Option<&str> {
    record
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| is_key(id))
}

/// A record set holding `records`, sorted by id. Refuses a record with no id
/// that is a key, or two with one id.
pub fn write(records: &[Value]) -> Result<Vec<u8>, String> {
    let mut sorted: Vec<(&str, &Value)> = Vec::with_capacity(records.len());
    for record in records {
        let id = id_of(record).ok_or("a record in a set needs an id that is a key")?;
        sorted.push((id, record));
    }
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    if let Some(pair) = sorted.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(format!("two records have the id {}", pair[0].0));
    }
    Ok(sorted.iter().flat_map(|(_, r)| canonical_line(r)).collect())
}

/// What a record set's manifest entry says it holds.
#[derive(Clone, Copy, Debug)]
pub struct Expect<'a> {
    pub record_type: &'a str,
    pub record_version: u64,
    pub count: u64,
    pub sha256: &'a str,
}

/// Reads a record set as a stream. Each record [`Reader::next_record`] yields
/// is provisional: only [`Reader::finish`] says whether the whole file is
/// what the manifest promised.
pub struct Reader<'a, R: Read> {
    input: BufReader<R>,
    expect: Expect<'a>,
    hasher: Sha256,
    line: u64,
    last_id: Option<String>,
    failed: bool,
    ended: bool,
    final_newline: bool,
}

impl<'a, R: Read> Reader<'a, R> {
    pub fn new(input: R, expect: Expect<'a>) -> Self {
        Reader {
            input: BufReader::new(input),
            expect,
            hasher: Sha256::new(),
            line: 0,
            last_id: None,
            failed: false,
            ended: false,
            final_newline: true,
        }
    }

    /// The next record, or the first problem with the file ("line n: …").
    /// After a problem it yields nothing more.
    pub fn next_record(&mut self) -> Option<Result<Value, String>> {
        if self.failed || self.ended {
            return None;
        }
        let mut raw = Vec::new();
        let read = (&mut self.input)
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut raw);
        let n = self.line + 1;
        match read {
            Err(e) => return Some(self.fail(format!("line {n}: {e}"))),
            Ok(0) => {
                self.ended = true;
                return None;
            }
            Ok(_) => {}
        }
        self.hasher.update(&raw);
        if raw.len() > MAX_LINE_BYTES {
            return Some(self.fail(format!("line {n}: longer than {MAX_LINE_BYTES} bytes")));
        }
        self.line = n;
        if raw.last() != Some(&b'\n') {
            self.final_newline = false;
            self.ended = true;
            return Some(self.fail(format!("line {n}: the file doesn't end with \\n")));
        }
        Some(self.check_line(n, &raw))
    }

    fn check_line(&mut self, n: u64, raw: &[u8]) -> Result<Value, String> {
        let body = &raw[..raw.len() - 1];
        if body.is_empty() {
            return self.fail(format!("line {n}: blank line"));
        }
        if body.last() == Some(&b'\r') {
            return self.fail(format!("line {n}: ends with \\r\\n, not \\n"));
        }
        let record: Value = match serde_json::from_slice(body) {
            Ok(Value::Object(map)) => Value::Object(map),
            Ok(_) => return self.fail(format!("line {n}: not a JSON object")),
            Err(e) => return self.fail(format!("line {n}: not JSON: {e}")),
        };
        if canonical_line(&record) != raw {
            return self.fail(format!(
                "line {n}: not canonical (compact, keys sorted, text as UTF-8)"
            ));
        }
        let (want_type, want_version) = (self.expect.record_type, self.expect.record_version);
        if record.get("$type").and_then(Value::as_str) != Some(want_type)
            || record.get("version").and_then(Value::as_u64) != Some(want_version)
        {
            return self.fail(format!(
                "line {n}: not a {want_type} version {want_version} record"
            ));
        }
        let Some(id) = id_of(&record).map(str::to_owned) else {
            return self.fail(format!("line {n}: no id that is a key"));
        };
        if let Some(last) = &self.last_id {
            if id == *last {
                return self.fail(format!("line {n}: repeats the id {id}"));
            }
            if id.as_bytes() < last.as_bytes() {
                return self.fail(format!("line {n}: out of order (ids are sorted as bytes)"));
            }
        }
        self.last_id = Some(id);
        Ok(record)
    }

    fn fail<T>(&mut self, problem: String) -> Result<T, String> {
        self.failed = true;
        Err(problem)
    }

    /// Reads whatever is left and checks the end: every line sound, the
    /// final `\n`, the count and the SHA-256. `Ok` is the number of records.
    pub fn finish(mut self) -> Result<u64, String> {
        while let Some(record) = self.next_record() {
            record?;
        }
        if self.failed {
            return Err("the record set has a bad line".to_owned());
        }
        if !self.final_newline {
            return Err("the file doesn't end with \\n".to_owned());
        }
        if self.line != self.expect.count {
            return Err(format!(
                "count is {} but the file has {} lines",
                self.expect.count, self.line
            ));
        }
        let sha = hex(&self.hasher.finalize());
        if sha != self.expect.sha256 {
            return Err("its sha256 doesn't match the manifest".to_owned());
        }
        Ok(self.line)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Checks a record set held in memory and returns its records.
pub fn check(bytes: &[u8], expect: Expect<'_>) -> Result<Vec<Value>, Vec<String>> {
    let mut reader = Reader::new(bytes, expect);
    let mut records = Vec::new();
    while let Some(record) = reader.next_record() {
        match record {
            Ok(record) => records.push(record),
            Err(problem) => return Err(vec![problem]),
        }
    }
    reader.finish().map_err(|problem| vec![problem])?;
    Ok(records)
}
