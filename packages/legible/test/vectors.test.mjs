// Runs the spec's vectors against the Node build (dist/node), so the
// WebAssembly package is held to the same cases as the Rust crate.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";

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
