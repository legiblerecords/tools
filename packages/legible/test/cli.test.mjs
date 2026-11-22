// Runs bin/legible.mjs end to end: schemas, validation, and bundles plain
// and encrypted with age.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { generateIdentity, identityToRecipient } from "age-encryption";

const bin = fileURLToPath(new URL("../bin/legible.mjs", import.meta.url));

function run(cwd, args, env = {}) {
  const { LEGIBLE_PASSPHRASE: _, ...inherited } = process.env;
  const result = spawnSync(process.execPath, [bin, ...args], {
    cwd,
    env: { ...inherited, ...env },
    input: "",
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

const SCHEMA = `type: tech.example.controls.control
version: 1
title: control
fields:
  id: slug
  title: string
  related?:
    items: ref(control)
  evidence?:
    items: attachment
`;

/** A directory holding a schema, two records and an attachment. */
function workspace() {
  const dir = mkdtempSync(join(tmpdir(), "legible-"));
  writeFileSync(join(dir, "control.yaml"), SCHEMA);
  mkdirSync(join(dir, "in"));
  const evidence = Buffer.from("%PDF-1.4 invented evidence\n");
  writeFileSync(join(dir, "in", "review.pdf"), evidence);
  const sha256 = createHash("sha256").update(evidence).digest("hex");
  const record = (id, extra) =>
    JSON.stringify({ $type: "tech.example.controls.control", version: 1, id, title: id.toUpperCase(), ...extra });
  writeFileSync(join(dir, "in", "mfa.json"), record("mfa", { evidence: [{ sha256, name: "review.pdf", media_type: "application/pdf" }] }));
  writeFileSync(join(dir, "in", "sso.json"), record("sso", { related: ["control:mfa"] }));
  return dir;
}

const BASE = ["--base", "https://example.org/schemas/"];

test("expand, lint and validate", () => {
  const dir = workspace();
  const expanded = run(dir, ["expand", "control.yaml", ...BASE]);
  assert.equal(expanded.status, 0, expanded.stderr);
  const schema = JSON.parse(expanded.stdout);
  assert.equal(schema.$id, "https://example.org/schemas/tech.example.controls.control/v1.json");
  assert.equal(run(dir, ["lint", "control.yaml", ...BASE]).status, 0);

  const good = run(dir, ["validate", "-s", "control.yaml", ...BASE, "in/mfa.json", "in/sso.json"]);
  assert.equal(good.status, 0, good.stdout + good.stderr);
  writeFileSync(join(dir, "bad.json"), JSON.stringify({ $type: "tech.example.controls.control", version: 1, id: "Not A Slug" }));
  const bad = run(dir, ["validate", "-s", "control.yaml", ...BASE, "bad.json"]);
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /bad\.json: \/id: /);
  assert.match(bad.stdout, /title/);
});

test("pack, verify and unpack a plain bundle", () => {
  const dir = workspace();
  const packed = run(dir, ["bundle", "pack", "in", "-o", "b.zip", "-s", "control.yaml", ...BASE]);
  assert.equal(packed.status, 0, packed.stderr);
  assert.match(packed.stderr, /attachment review\.pdf: \{"sha256":"[0-9a-f]{64}"/);
  const again = run(dir, ["bundle", "pack", "in", "-o", "c.zip", "-s", "control.yaml", ...BASE]);
  assert.equal(again.status, 0);
  assert.deepEqual(readFileSync(join(dir, "b.zip")), readFileSync(join(dir, "c.zip")), "the same files pack to the same bytes");

  const verified = run(dir, ["bundle", "verify", "b.zip", "-s", "control.yaml", ...BASE]);
  assert.equal(verified.status, 0, verified.stdout + verified.stderr);

  const unpacked = run(dir, ["bundle", "unpack", "b.zip", "-d", "out"]);
  assert.equal(unpacked.status, 0, unpacked.stdout + unpacked.stderr);
  assert.deepEqual(readdirSync(join(dir, "out")).sort(), ["files", "manifest.json", "records"]);
  assert.deepEqual(readdirSync(join(dir, "out", "records", "control")).sort(), ["mfa.json", "sso.json"]);
  const manifest = JSON.parse(readFileSync(join(dir, "out", "manifest.json"), "utf8"));
  assert.equal(manifest.$type, "org.legiblerecords.bundle");
  assert.equal(manifest.files.length, 3);

  const twice = run(dir, ["bundle", "unpack", "b.zip", "-d", "out"]);
  assert.equal(twice.status, 2);
  assert.match(twice.stderr, /not empty/);
});

test("a broken reference fails verification", () => {
  const dir = workspace();
  writeFileSync(
    join(dir, "in", "sso.json"),
    JSON.stringify({ $type: "tech.example.controls.control", version: 1, id: "sso", title: "SSO", related: ["control:nope"] }),
  );
  assert.equal(run(dir, ["bundle", "pack", "in", "-o", "b.zip"]).status, 0);
  const verified = run(dir, ["bundle", "verify", "b.zip", "-s", "control.yaml", ...BASE]);
  assert.equal(verified.status, 1);
  assert.match(verified.stdout, /refers to control:nope/);
  const unpacked = run(dir, ["bundle", "unpack", "b.zip", "-d", "out", "-s", "control.yaml", ...BASE]);
  assert.equal(unpacked.status, 1);
  assert.throws(() => readdirSync(join(dir, "out")), "nothing is written from a bundle that fails");
});

test("not a zip", () => {
  const dir = workspace();
  writeFileSync(join(dir, "b.zip"), "hello");
  const verified = run(dir, ["bundle", "verify", "b.zip"]);
  assert.equal(verified.status, 1);
  assert.match(verified.stdout, /not a zip file/);
});

test("a passphrase from LEGIBLE_PASSPHRASE, armored", () => {
  const dir = workspace();
  const env = { LEGIBLE_PASSPHRASE: "correct horse battery staple" };
  const packed = run(dir, ["bundle", "pack", "in", "-o", "b.zip.age", "--passphrase", "--armor"], env);
  assert.equal(packed.status, 0, packed.stderr);
  assert.doesNotMatch(packed.stderr, /passphrase:/, "a passphrase that was given isn't printed");
  assert.match(readFileSync(join(dir, "b.zip.age"), "utf8"), /^-----BEGIN AGE ENCRYPTED FILE-----/);

  const verified = run(dir, ["bundle", "verify", "b.zip.age"], env);
  assert.equal(verified.status, 0, verified.stdout + verified.stderr);
  const wrong = run(dir, ["bundle", "verify", "b.zip.age"], { LEGIBLE_PASSPHRASE: "wrong" });
  assert.equal(wrong.status, 2);
  assert.match(wrong.stderr, /couldn't decrypt/);
  const none = run(dir, ["bundle", "verify", "b.zip.age"]);
  assert.equal(none.status, 2);
  assert.match(none.stderr, /set LEGIBLE_PASSPHRASE/);
});

test("a generated passphrase is printed once, to stderr", () => {
  const dir = workspace();
  const packed = run(dir, ["bundle", "pack", "in", "-o", "b.age", "--passphrase"]);
  assert.equal(packed.status, 0, packed.stderr);
  const passphrase = packed.stderr.match(/^passphrase: ([a-z0-9-]+)$/m)?.[1];
  assert.match(passphrase ?? "", /^([a-z2-9]{5}-){4}[a-z2-9]{5}$/);
  assert.equal(packed.stdout, "");
  assert.ok(readFileSync(join(dir, "b.age")).subarray(0, 19).equals(Buffer.from("age-encryption.org/")));
  const unpacked = run(dir, ["bundle", "unpack", "b.age", "-d", "out"], { LEGIBLE_PASSPHRASE: passphrase });
  assert.equal(unpacked.status, 0, unpacked.stdout + unpacked.stderr);
});

test("age recipients and identities", async () => {
  const dir = workspace();
  const identity = await generateIdentity();
  const recipient = await identityToRecipient(identity);
  writeFileSync(join(dir, "key.txt"), `# created: just now\n# public key: ${recipient}\n${identity}\n`);
  const packed = run(dir, ["bundle", "pack", "in", "-o", "b.age", "-r", recipient]);
  assert.equal(packed.status, 0, packed.stderr);
  const unpacked = run(dir, ["bundle", "unpack", "b.age", "-d", "out", "-i", "key.txt"]);
  assert.equal(unpacked.status, 0, unpacked.stdout + unpacked.stderr);

  const other = await generateIdentity();
  writeFileSync(join(dir, "other.txt"), `${other}\n`);
  const refused = run(dir, ["bundle", "verify", "b.age", "-i", "other.txt"]);
  assert.equal(refused.status, 2);

  const both = run(dir, ["bundle", "pack", "in", "-o", "x.age", "-r", recipient, "--passphrase"]);
  assert.equal(both.status, 2);
  const armorAlone = run(dir, ["bundle", "pack", "in", "-o", "x.zip", "--armor"]);
  assert.equal(armorAlone.status, 2);
});
