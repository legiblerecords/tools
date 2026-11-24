//! Record sets (spec/records.md § Record sets): writing, checking, streaming,
//! and how bundles pack and verify them.

use std::io::Cursor;

use legible_records::bundle::{
    open, pack_with, sha256_hex, verify, Input, Limits, PackOptions, SetMode,
};
use legible_records::record_set::{self, Expect, Reader, MAX_LINE_BYTES, SET_THRESHOLD};
use serde_json::{json, Value};

fn alert(id: &str, version: u64) -> Value {
    json!({"$type": "example.alert", "version": version, "id": id, "severity": "high"})
}

fn alerts(n: usize, version: u64) -> Vec<Value> {
    (0..n)
        .map(|i| alert(&format!("a-{i:05}"), version))
        .collect()
}

fn expect_for<'a>(bytes: &[u8], sha: &'a str, version: u64) -> Expect<'a> {
    Expect {
        record_type: "example.alert",
        record_version: version,
        count: bytes.iter().filter(|b| **b == b'\n').count() as u64,
        sha256: sha,
    }
}

fn input(name: &str, value: &Value) -> Input {
    Input {
        name: name.to_owned(),
        bytes: serde_json::to_vec(value).unwrap(),
    }
}

fn manifest_paths(manifest: &Value) -> Vec<String> {
    manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn streaming_reader_yields_then_finish_decides() {
    let original = record_set::write(&alerts(3, 1)).unwrap();
    let sha = sha256_hex(&original);
    // Change one value on the last line, keeping the line canonical.
    let text = String::from_utf8(original.clone()).unwrap();
    let at = text.rfind("high").unwrap();
    let tampered = format!("{}hogh{}", &text[..at], &text[at + 4..]).into_bytes();
    let mut reader = Reader::new(
        Cursor::new(tampered.clone()),
        expect_for(&tampered, &sha, 1),
    );
    let mut yielded = 0;
    while let Some(record) = reader.next_record() {
        record.expect("each line is a sound record on its own");
        yielded += 1;
    }
    assert_eq!(yielded, 3, "records come out before the end is checked");
    let end = reader.finish().unwrap_err();
    assert!(end.contains("sha256"), "{end}");
}

#[test]
fn crlf_line_is_refused_with_line_number() {
    let lf = record_set::write(&alerts(2, 1)).unwrap();
    let crlf = String::from_utf8(lf)
        .unwrap()
        .replace('\n', "\r\n")
        .into_bytes();
    let sha = sha256_hex(&crlf);
    let problems = record_set::check(&crlf, expect_for(&crlf, &sha, 1)).unwrap_err();
    assert!(
        problems.iter().any(|p| p.contains("line 1")),
        "{problems:?}"
    );
}

#[test]
fn unicode_round_trip_is_byte_identical() {
    let records =
        vec![json!({"$type": "example.alert", "version": 1, "id": "a-1", "title": "Café 漢字"})];
    let bytes = record_set::write(&records).unwrap();
    assert!(String::from_utf8(bytes.clone())
        .unwrap()
        .contains("Café 漢字"));
    assert!(!String::from_utf8(bytes.clone())
        .unwrap()
        .contains("\\u00e9"));
    let sha = sha256_hex(&bytes);
    assert_eq!(
        record_set::check(&bytes, expect_for(&bytes, &sha, 1)).unwrap(),
        records
    );
}

#[test]
fn threshold_1000_is_files_1001_is_set() {
    assert_eq!(SET_THRESHOLD, 1000);
    for (n, as_set) in [(1000, false), (1001, true)] {
        let inputs: Vec<Input> = alerts(n, 1)
            .iter()
            .map(|a| input(&format!("{}.json", a["id"].as_str().unwrap()), a))
            .collect();
        let packed = pack_with(&inputs, &[], &PackOptions::default()).unwrap();
        let paths = manifest_paths(&packed.manifest);
        assert_eq!(
            paths.contains(&"records/alert.ndjson".to_owned()),
            as_set,
            "{n}"
        );
        assert_eq!(paths.len(), if as_set { 1 } else { n }, "{n}");
        if as_set {
            assert_eq!(packed.manifest["files"][0]["count"], json!(1001));
        }
        let opened = open(&packed.zip, Limits::default()).unwrap();
        assert!(verify(&opened, &[]).problems.is_empty());
    }
}

#[test]
fn set_mode_never_and_kinds() {
    let inputs: Vec<Input> = alerts(3, 1)
        .iter()
        .map(|a| input(&format!("{}.json", a["id"].as_str().unwrap()), a))
        .collect();
    let forced = PackOptions {
        sets: SetMode::Kinds(vec!["alert".to_owned()]),
        ..PackOptions::default()
    };
    let paths = manifest_paths(&pack_with(&inputs, &[], &forced).unwrap().manifest);
    assert_eq!(paths, vec!["records/alert.ndjson".to_owned()]);
    let many: Vec<Input> = alerts(1001, 1)
        .iter()
        .map(|a| input(&format!("{}.json", a["id"].as_str().unwrap()), a))
        .collect();
    let never = PackOptions {
        sets: SetMode::Never,
        ..PackOptions::default()
    };
    assert_eq!(
        manifest_paths(&pack_with(&many, &[], &never).unwrap().manifest).len(),
        1001
    );
}

#[test]
fn line_over_cap_is_refused() {
    let big = json!({"$type": "example.alert", "version": 1, "id": "a-1", "blob": "x".repeat(MAX_LINE_BYTES)});
    let bytes = record_set::canonical_line(&big);
    let sha = sha256_hex(&bytes);
    let problems = record_set::check(&bytes, expect_for(&bytes, &sha, 1)).unwrap_err();
    assert!(
        problems.iter().any(|p| p.contains("line 1")),
        "{problems:?}"
    );
}

#[test]
fn write_refuses_missing_and_repeated_ids() {
    assert!(record_set::write(&[json!({"$type": "example.alert", "version": 1})]).is_err());
    assert!(record_set::write(&[alert("a-1", 1), alert("a-1", 1)]).is_err());
}

#[test]
fn ndjson_input_is_kept_as_is() {
    let bytes = record_set::write(&alerts(3, 1)).unwrap();
    let inputs = vec![Input {
        name: "alert.ndjson".to_owned(),
        bytes: bytes.clone(),
    }];
    let packed = pack_with(&inputs, &[], &PackOptions::default()).unwrap();
    let opened = open(&packed.zip, Limits::default()).unwrap();
    assert_eq!(opened.files["records/alert.ndjson"], bytes);
    assert_eq!(packed.manifest["files"][0]["count"], json!(3));
    assert!(verify(&opened, &[]).problems.is_empty());
}

#[test]
fn bad_ndjson_input_is_refused() {
    let unsorted = [
        record_set::canonical_line(&alert("b", 1)),
        record_set::canonical_line(&alert("a", 1)),
    ]
    .concat();
    let inputs = vec![Input {
        name: "alert.ndjson".to_owned(),
        bytes: unsorted,
    }];
    let problems = pack_with(&inputs, &[], &PackOptions::default()).unwrap_err();
    assert!(
        problems.iter().any(|p| p.contains("line 2")),
        "{problems:?}"
    );
}

#[test]
fn mixed_versions_pack_one_set_and_files() {
    let mut inputs: Vec<Input> = alerts(1001, 2)
        .iter()
        .map(|a| input(&format!("{}.json", a["id"].as_str().unwrap()), a))
        .collect();
    for i in 0..5 {
        let a = alert(&format!("v1-{i}"), 1);
        inputs.push(input(&format!("v1-{i}.json"), &a));
    }
    let packed = pack_with(&inputs, &[], &PackOptions::default()).unwrap();
    let paths = manifest_paths(&packed.manifest);
    assert!(paths.contains(&"records/alert.ndjson".to_owned()));
    assert_eq!(
        paths
            .iter()
            .filter(|p| p.starts_with("records/alert/"))
            .count(),
        5
    );
    let opened = open(&packed.zip, Limits::default()).unwrap();
    assert!(verify(&opened, &[]).problems.is_empty());
}

#[test]
fn reference_into_a_set_resolves() {
    let note_schema = json!({
        "$id": "https://example.org/schemas/example.note/v1.json",
        "type": "object",
        "properties": {
            "$type": {"const": "example.note"},
            "version": {"const": 1},
            "about": {"$ref": "x#/$defs/refString", "ref": "alert"}
        }
    });
    let set = record_set::write(&alerts(2, 1)).unwrap();
    let pack = |about: &str| {
        let inputs = vec![
            Input {
                name: "alert.ndjson".to_owned(),
                bytes: set.clone(),
            },
            input(
                "n.json",
                &json!({"$type": "example.note", "version": 1, "id": "n", "about": about}),
            ),
        ];
        let packed = pack_with(
            &inputs,
            std::slice::from_ref(&note_schema),
            &PackOptions::default(),
        )
        .unwrap();
        verify(
            &open(&packed.zip, Limits::default()).unwrap(),
            std::slice::from_ref(&note_schema),
        )
        .problems
    };
    assert!(
        pack("alert:a-00001").is_empty(),
        "{:?}",
        pack("alert:a-00001")
    );
    assert!(!pack("alert:a-99999").is_empty());
}

#[test]
fn numbers_are_written_as_ecmascript_writes_them() {
    let record: Value = serde_json::from_str(
        r#"{"a":7.5,"b":0.00001,"c":1e-7,"d":1e21,"e":1e20,"f":123456789,"g":-3,"h":0,"i":0.5,"j":1e-6,"k":5e-324,"l":-0.0}"#,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(record_set::canonical_line(&record)).unwrap(),
        "{\"a\":7.5,\"b\":0.00001,\"c\":1e-7,\"d\":1e+21,\"e\":100000000000000000000,\"f\":123456789,\"g\":-3,\"h\":0,\"i\":0.5,\"j\":0.000001,\"k\":5e-324,\"l\":0}\n"
    );
}

#[test]
fn escapes_are_only_what_json_requires() {
    let record = json!({"s": "a\"b\\c\u{8}\u{c}\n\r\t\u{1}\u{1f}/\u{7f}\u{2028}é"});
    assert_eq!(
        String::from_utf8(record_set::canonical_line(&record)).unwrap(),
        "{\"s\":\"a\\\"b\\\\c\\b\\f\\n\\r\\t\\u0001\\u001f/\u{7f}\u{2028}é\"}\n"
    );
}

#[test]
fn keys_sort_by_utf8_bytes() {
    // U+FF61 sorts before U+1F600 by UTF-8 bytes; by UTF-16 code units it sorts after.
    let record = json!({"\u{1F600}": 1, "\u{FF61}": 2, "a": 3});
    assert_eq!(
        String::from_utf8(record_set::canonical_line(&record)).unwrap(),
        "{\"a\":3,\"\u{FF61}\":2,\"\u{1F600}\":1}\n"
    );
}

#[test]
fn a_set_named_by_title_verifies_without_the_schema() {
    let schema = json!({
        "$id": "https://example.org/schemas/example.alert/v1.json",
        "title": "vuln-alert",
        "type": "object",
        "properties": {"$type": {"const": "example.alert"}, "version": {"const": 1}}
    });
    let inputs: Vec<Input> = alerts(2, 1)
        .iter()
        .map(|a| input(&format!("{}.json", a["id"].as_str().unwrap()), a))
        .collect();
    let options = PackOptions {
        sets: SetMode::Kinds(vec!["vuln-alert".to_owned()]),
        ..PackOptions::default()
    };
    let packed = pack_with(&inputs, std::slice::from_ref(&schema), &options).unwrap();
    assert_eq!(
        manifest_paths(&packed.manifest),
        vec!["records/vuln-alert.ndjson".to_owned()]
    );
    let opened = open(&packed.zip, Limits::default()).unwrap();
    assert!(
        verify(&opened, &[]).problems.is_empty(),
        "{:?}",
        verify(&opened, &[]).problems
    );
}

#[test]
fn reader_stops_once_lines_exceed_count() {
    let bytes = record_set::write(&alerts(3, 1)).unwrap();
    let sha = sha256_hex(&bytes);
    let expect = Expect {
        record_type: "example.alert",
        record_version: 1,
        count: 1,
        sha256: &sha,
    };
    let mut reader = Reader::new(Cursor::new(bytes), expect);
    assert!(reader.next_record().unwrap().is_ok());
    let second = reader.next_record().unwrap().unwrap_err();
    assert!(
        second.contains("line 2") && second.contains("count"),
        "{second}"
    );
    assert!(reader.next_record().is_none(), "nothing after a problem");
}

#[test]
fn a_byte_order_mark_is_named() {
    let mut bytes = "\u{feff}".as_bytes().to_vec();
    bytes.extend(record_set::write(&alerts(1, 1)).unwrap());
    let sha = sha256_hex(&bytes);
    let problems = record_set::check(&bytes, expect_for(&bytes, &sha, 1)).unwrap_err();
    assert!(
        problems
            .iter()
            .any(|p| p.contains("line 1") && p.contains("byte order mark")),
        "{problems:?}"
    );
}

#[test]
fn set_for_a_kind_with_no_records_is_refused() {
    let inputs: Vec<Input> = alerts(2, 1)
        .iter()
        .map(|a| input(&format!("{}.json", a["id"].as_str().unwrap()), a))
        .collect();
    let options = PackOptions {
        sets: SetMode::Kinds(vec!["alret".to_owned()]),
        ..PackOptions::default()
    };
    let problems = pack_with(&inputs, &[], &options).unwrap_err();
    assert!(problems.iter().any(|p| p.contains("alret")), "{problems:?}");
}

#[test]
fn threshold_counts_every_version_of_a_kind() {
    let mut inputs: Vec<Input> = Vec::new();
    for version in [1, 2] {
        for i in 0..600 {
            let a = alert(&format!("v{version}-{i:04}"), version);
            inputs.push(input(&format!("v{version}-{i}.json"), &a));
        }
    }
    let packed = pack_with(&inputs, &[], &PackOptions::default()).unwrap();
    let set = packed.manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "records/alert.ndjson")
        .expect("1,200 alerts make a set");
    assert_eq!(
        set["record_version"],
        json!(2),
        "ties go to the higher version"
    );
    assert_eq!(set["count"], json!(600));
    let opened = open(&packed.zip, Limits::default()).unwrap();
    assert!(verify(&opened, &[]).problems.is_empty());
}
