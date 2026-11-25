// Runs the spec's vectors against the Node build (dist/node), so the
// WebAssembly package is held to the same cases as the Rust crate.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync, readdirSync } from "node:fs";

const require = createRequire(import.meta.url);
const legible = require("../dist/legible_records_wasm.cjs");

const vectors = (name) =>
  JSON.parse(
    readFileSync(new URL(`../../../crates/legible-records/tests/vectors/${name}`, import.meta.url)),
  ).cases;

for (const file of ["schema-language.json", "schema-language-published.json"]) {
  test(file, () => {
    const failures = [];
    for (const c of vectors(file)) {
      const options = c.options ?? undefined;
      if (c.short !== undefined) {
        const got = legible.expand(c.short, c.schema, options);
        const want = c.expect.body
          ? { ok: true, body: c.expect.body }
          : { ok: false, problems: c.expect.problems };
        try {
          assert.deepStrictEqual(got, want);
        } catch {
          failures.push(`${c.name}: expected ${JSON.stringify(want)} got ${JSON.stringify(got)}`);
        }
      } else {
        const got = legible.generate(c.body, c.schema, options);
        if (got !== c.expect.short) failures.push(`${c.name}: expected ${JSON.stringify(c.expect.short)} got ${JSON.stringify(got)}`);
      }
    }
    assert.deepEqual(failures, []);
  });
}

test("restricted-yaml.json", () => {
  const failures = [];
  for (const c of vectors("restricted-yaml.json")) {
    const got = legible.parseYaml(c.yaml);
    const got_as_vector = got.ok ? { value: got.value } : { error: got.error.reason };
    try {
      assert.deepStrictEqual(got_as_vector, c.expect);
    } catch {
      failures.push(`${c.name}: expected ${JSON.stringify(c.expect).slice(0, 120)} got ${JSON.stringify(got_as_vector).slice(0, 120)}`);
    }
  }
  assert.deepEqual(failures, []);
});

test("lint and checkCompat", () => {
  const options = { base: "https://example.org/schemas/" };
  const v1 = legible.expand("type: org.example.thing\nversion: 1\nfields:\n  level: known(a, b)\n  note?: string\n", "thing", options);
  assert.equal(v1.ok, true);
  assert.deepEqual(legible.lint(v1.body), []);

  const v1b = legible.expand("type: org.example.thing\nversion: 1\nfields:\n  level: known(a, b, c)\n  note: string\n", "thing", options);
  assert.deepEqual(
    legible.checkCompat(v1.body, v1b.body).map((b) => b.message),
    ["note became required"],
  );
  assert.deepEqual(
    legible.lint({ type: "object", additionalProperties: false }).map((f) => f.pointer),
    ["", "/additionalProperties"],
  );
});

test("the web build loads the same module", async () => {
  const web = await import("../dist/legible_records_wasm.js");
  const bytes = readFileSync(new URL("../dist/legible_records_wasm_bg.wasm", import.meta.url));
  await web.default({ module_or_path: bytes });
  const result = web.expand("fields:\n  x: known(a)\n", "t");
  assert.deepEqual(result.body.properties.x, { type: "string", examples: ["a"] });
});

// Vectors this build doesn't pass yet; each must still fail, so the list only shrinks.
const PENDING = [];

test("signed bundle vectors", () => {
  const dir = new URL("../../../crates/legible-records/tests/vectors/bundles/", import.meta.url);
  const failures = [];
  let count = 0;
  for (const name of readdirSync(dir).sort()) {
    const c = JSON.parse(readFileSync(new URL(`${name}/case.json`, dir)));
    const zip = readFileSync(new URL(`${name}/bundle.zip`, dir));
    const options = {
      pins: c.trust.pins.map((p) => ({ publisher: p.publisher, id: p.id, alg: p.alg, publicKey: p.public_key })),
      keySets: c.trust.key_sets.map((s) => Buffer.from(JSON.stringify(s))),
    };
    if (c.expected_publisher) options.expectedPublisher = c.expected_publisher;
    const now = Date.parse(c.now ?? "2026-12-01T00:00:00Z");
    let opened;
    try {
      // The zip's entry names are read first.
      opened = legible.Bundle.open(zip);
    } catch {
      opened = undefined;
    }
    let got = { error: "bad_bundle" };
    if (opened) {
      try {
        got = opened.verifySignature(options);
        // The signature is checked before the bundle's own checks.
        if (opened.verify([], now).problems.length) got = { error: "bad_bundle" };
      } catch (e) {
        got = { error: e.message };
      }
      opened.free();
    }
    let passes = true;
    try {
      assert.deepStrictEqual(got, c.expect);
    } catch {
      passes = false;
    }
    if (!passes && !PENDING.includes(c.name)) {
      failures.push(`${c.name}: expected ${JSON.stringify(c.expect)} got ${JSON.stringify(got)}`);
    } else if (passes && PENDING.includes(c.name)) {
      failures.push(`${c.name}: passes; take it off PENDING`);
    }
    count++;
  }
  assert.ok(count >= 10, `only ${count} bundle vectors`);
  assert.deepEqual(failures, []);
});

test("generateKey and signBundle", () => {
  const { secretKey, keySetEntry } = legible.generateKey("acme.example", "2026-11");
  assert.ok(secretKey instanceof Uint8Array);
  assert.equal(keySetEntry.id, "2026-11");
  assert.equal(keySetEntry.alg, "ed25519");
  assert.match(keySetEntry.created_at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  assert.throws(() => legible.generateKey("Not A Domain", "x"));
  const builder = new legible.BundleBuilder();
  builder.add("a.txt", Buffer.from("hi"));
  const packed = builder.finish([], undefined);
  const signed = legible.signBundle(packed.zip(), secretKey);
  const opened = legible.Bundle.open(signed);
  const pins = [{ publisher: "acme.example", id: "2026-11", publicKey: keySetEntry.public_key }];
  assert.deepEqual(opened.verifySignature({ pins }), { status: "verified", publisher: "acme.example", key: "2026-11" });
  assert.throws(() => legible.signBundle(signed, secretKey), /already signed/);
});

test("record sets: recordSet and Bundle.recordSets", () => {
  const dir = new URL("../../../crates/legible-records/tests/vectors/bundles/", import.meta.url);
  const valid = legible.Bundle.open(readFileSync(new URL("record-set-valid/bundle.zip", dir)));
  const sets = valid.recordSets();
  assert.deepEqual(sets, [{ path: "records/alert.ndjson", recordType: "example.alert", recordVersion: 1, count: 3 }]);
  const entry = valid.manifest().files.find((f) => f.path === sets[0].path);
  const records = legible.recordSet(valid.file(sets[0].path), {
    recordType: sets[0].recordType,
    recordVersion: sets[0].recordVersion,
    count: sets[0].count,
    sha256: entry.sha256,
  });
  assert.deepEqual(records.map((r) => r.id), ["api-12", "api-7", "web-3"]);
  valid.free();

  const bad = legible.Bundle.open(readFileSync(new URL("unsorted-lines/bundle.zip", dir)));
  const badEntry = bad.manifest().files.find((f) => f.path === "records/alert.ndjson");
  assert.throws(
    () => legible.recordSet(bad.file("records/alert.ndjson"), {
      recordType: "example.alert", recordVersion: 1, count: badEntry.count, sha256: badEntry.sha256,
    }),
    /line 2/,
  );
  bad.free();
});

test("content-lines.json: contentLine and recordHash", () => {
  const file = JSON.parse(
    readFileSync(new URL("../../../crates/legible-records/tests/vectors/content-lines.json", import.meta.url)),
  );
  const failures = [];
  for (const c of file.cases) {
    // The record's text, as a file would hold it: whitespace and key order don't count.
    const text = new TextEncoder().encode(JSON.stringify(c.record, null, 2) + "\n");
    const line = new TextDecoder().decode(legible.contentLine(text));
    if (line !== c.content_line) failures.push(`${c.name}: line ${JSON.stringify(line)}`);
    const hash = legible.recordHash(text);
    if (hash !== c.sha256) failures.push(`${c.name}: hash ${hash}, expected ${c.sha256}`);
  }
  assert.deepEqual(failures, []);
  assert.ok(file.refused.length >= 5);
  for (const c of file.refused) {
    // Each is refused from its exact text, which JSON.parse would quietly change.
    const text = new TextEncoder().encode(c.record_text);
    assert.throws(() => legible.recordHash(text), Error, `${c.name} was accepted by recordHash`);
    assert.throws(() => legible.contentLine(text), Error, `${c.name} was accepted by contentLine`);
  }
});
