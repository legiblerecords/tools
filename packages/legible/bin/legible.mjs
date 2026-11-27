#!/usr/bin/env node
// legible: the Legible Records command-line tool, for Node.
//
// The same commands as the Rust `legible`, built on this package's
// WebAssembly, plus age encryption for bundles sent over email and other
// transports you don't trust. Exit status: 0 when everything passes, 1 when
// the input has problems, 2 when the tool couldn't run.

import { createRequire } from "node:module";
import { readFileSync, writeFileSync, readdirSync, lstatSync, mkdirSync, openSync, writeSync, closeSync, unlinkSync } from "node:fs";
import { basename, dirname, join, resolve, relative, sep, isAbsolute } from "node:path";
import { parseArgs } from "node:util";
import { randomInt } from "node:crypto";

const require = createRequire(import.meta.url);
const legible = require("../dist/legible_records_wasm.cjs");
const { version: VERSION } = require("../package.json");

/** Problems in the input: exit 1, after they've been printed. */
class Problems extends Error {}
/** The tool couldn't run: exit 2, with this message. */
class Failed extends Error {}

const USAGE = `legible ${VERSION}: Legible Records

Usage:
  legible expand <schema.yaml> [schema options]
  legible generate <schema.json> [schema options]
  legible lint <schema.yaml|.json> [schema options]
  legible check-compat <old> <new> [schema options]
  legible validate -s <schema>... <record.json|.ndjson>... [schema options]
  legible record hash <record.json>...
  legible bundle pack <file|dir>... -o <bundle> [-s <schema>]... [--set <kind>]... [--no-sets] [encryption]
  legible bundle unpack <bundle> -d <dir> [-s <schema>]... [-i <identity>] [trust]
  legible bundle verify <bundle> [-s <schema>]... [-i <identity>] [trust]
  legible bundle sign <bundle> -k <key> -o <signed-bundle>
  legible keys new --publisher <domain> --id <key-id> -o <key-file>

Trust (bundle verify, unpack): without it a signed bundle is reported unverified.
  --pin <publisher>/<id>=<public_key>  trust a key (base64url); repeat for several
  --key-set <file>    trust a publisher's keys.json; repeat for several

Schema options:
  --name <name>       the schema's name, for its own <name>.<def> references
  --base <url>        a published type's $id base, such as https://monorail.tech/schemas/
  --common <target>   where bare names such as date point
  --location <tmpl>   where <schema>.<def> points, with {name} for the schema

Encryption (bundle pack), with age (https://age-encryption.org):
  --passphrase        encrypt with a passphrase: LEGIBLE_PASSPHRASE, or a new one
                      printed to stderr. Send it by a different channel than the bundle.
  -r, --recipient <age1...>  encrypt to an age public key; repeat for several
  --armor             write ASCII armor, for pasting into email
Decryption (unpack, verify) is automatic: a passphrase from LEGIBLE_PASSPHRASE or a
prompt, or -i <file> with age identities (AGE-SECRET-KEY-1...).

Exit status: 0 when everything passes, 1 when the input has problems, 2 when the
tool couldn't run.
`;

const schemaOptions = {
  name: { type: "string" },
  base: { type: "string" },
  common: { type: "string" },
  location: { type: "string" },
};

async function main(argv) {
  const [command, ...rest] = argv;
  switch (command) {
    case undefined:
    case "-h":
    case "--help":
    case "help":
      process.stdout.write(USAGE);
      return;
    case "-V":
    case "--version":
      console.log(VERSION);
      return;
    case "expand": {
      const { positionals: [file], values } = parse(rest, schemaOptions, 1);
      console.log(JSON.stringify(loadSchema(file, values), null, 2));
      return;
    }
    case "generate": {
      const { positionals: [file], values } = parse(rest, schemaOptions, 1);
      const body = readJson(file);
      try {
        process.stdout.write(legible.generate(body, nameFor(file, values), expandOptions(values)));
      } catch (e) {
        throw new Failed(`${file}: ${message(e)}`);
      }
      return;
    }
    case "lint": {
      const { positionals: [file], values } = parse(rest, schemaOptions, 1);
      const findings = legible.lint(loadSchema(file, values));
      for (const f of findings) console.log(`${file}: ${f.pointer || "/"}: ${f.message}`);
      if (findings.length) throw new Problems();
      return;
    }
    case "check-compat": {
      const { positionals: [oldFile, newFile], values } = parse(rest, schemaOptions, 2);
      const breaks = legible.checkCompat(loadSchema(oldFile, values), loadSchema(newFile, values));
      for (const b of breaks) console.log(`${oldFile}: ${b.pointer || "/"}: ${b.message}`);
      if (breaks.length) throw new Problems();
      return;
    }
    case "validate": {
      const { positionals, values } = parse(rest, { ...schemaOptions, schema: { type: "string", short: "s", multiple: true } }, -1);
      if (!values.schema?.length) throw new Failed("validate needs at least one --schema");
      if (!positionals.length) throw new Failed("validate needs at least one record");
      await validate(values.schema.map((s) => loadSchema(s, values)), positionals);
      return;
    }
    case "record":
      return record(rest);
    case "bundle":
      return bundle(rest);
    case "keys":
      return keys(rest);
    default:
      throw new Failed(`unknown command ${command}; see legible --help`);
  }
}

async function bundle([action, ...rest]) {
  const schema = { type: "string", short: "s", multiple: true };
  const identity = { type: "string", short: "i", multiple: true };
  const trust = { pin: { type: "string", multiple: true }, "key-set": { type: "string", multiple: true } };
  switch (action) {
    case "pack": {
      const { positionals, values } = parse(
        rest,
        {
          ...schemaOptions,
          schema,
          output: { type: "string", short: "o" },
          passphrase: { type: "boolean" },
          recipient: { type: "string", short: "r", multiple: true },
          armor: { type: "boolean" },
          set: { type: "string", multiple: true },
          "no-sets": { type: "boolean" },
        },
        -1,
      );
      if (!positionals.length) throw new Failed("bundle pack needs files or directories to pack");
      if (values.set?.length && values["no-sets"]) throw new Failed("--set and --no-sets can't be used together");
      if (!values.output) throw new Failed("bundle pack needs -o <bundle>, or -o - for stdout");
      const schemas = (values.schema ?? []).map((s) => loadSchema(s, values));
      const builder = new legible.BundleBuilder();
      if (values.set?.length) builder.setKinds(values.set);
      if (values["no-sets"]) builder.noSets();
      try {
        for (const file of positionals.flatMap((p) => collect(p))) {
          builder.add(basename(file), readFileSync(file));
        }
        let packed;
        try {
          packed = builder.finish(schemas, { app: "legible", build: VERSION });
        } catch (e) {
          for (const line of message(e).split("\n")) console.error(line);
          throw new Problems();
        }
        try {
          for (const a of packed.attachments()) console.error(`attachment ${a.name}: ${JSON.stringify(a)}`);
          let bytes = packed.zip();
          if (values.passphrase || values.recipient?.length) {
            bytes = await encrypt(bytes, values);
          } else if (values.armor) {
            throw new Failed("--armor is for encrypted bundles; add --passphrase or --recipient");
          }
          writeOutput(values.output, bytes);
        } finally {
          packed.free();
        }
      } finally {
        builder.free();
      }
      return;
    }
    case "verify": {
      const { positionals: [file], values } = parse(rest, { ...schemaOptions, schema, identity, ...trust }, 1);
      const opened = await openBundle(file, values);
      try {
        verify(file, opened, values);
      } finally {
        opened.free();
      }
      return;
    }
    case "unpack": {
      const { positionals: [file], values } = parse(rest, { ...schemaOptions, schema, identity, ...trust, directory: { type: "string", short: "d" } }, 1);
      if (!values.directory) throw new Failed("bundle unpack needs -d <directory>");
      const opened = await openBundle(file, values);
      try {
        verify(file, opened, values);
        unpack(opened, values.directory);
      } finally {
        opened.free();
      }
      return;
    }
    case "sign": {
      const { positionals: [file], values } = parse(rest, { key: { type: "string", short: "k" }, output: { type: "string", short: "o" } }, 1);
      if (!values.key) throw new Failed("bundle sign needs -k <key>");
      if (!values.output) throw new Failed("bundle sign needs -o <signed-bundle>, or -o - for stdout");
      const secret = readInput(values.key);
      try {
        const zip = readInput(file);
        let signed;
        try {
          signed = legible.signBundle(zip, secret);
        } catch (e) {
          // A bad key file is the tool failing; the bundle's problems are the input's.
          if (/secret key file/.test(message(e))) throw new Failed(`${values.key}: ${message(e)}`);
          for (const line of message(e).split("\n")) console.log(`${file}: ${line}`);
          throw new Problems();
        }
        writeOutput(values.output, signed);
      } finally {
        secret.fill(0);
      }
      return;
    }
    default:
      throw new Failed(`unknown bundle command ${action ?? ""}; use pack, unpack, verify or sign`);
  }
}

// Prints each record's content hash, the SHA-256 of its canonical line without
// produced_by and source: what an external reference's sha256 pins. A record
// with no canonical form is a problem, and the others are still hashed.
function record([action, ...rest]) {
  if (action !== "hash") throw new Failed(`unknown record command ${action ?? ""}; use hash`);
  const { positionals: files } = parse(rest, {}, -1);
  if (!files.length) throw new Failed("record hash needs at least one record");
  let clean = true;
  for (const file of files) {
    const text = readInput(file);
    try {
      console.log(`${legible.recordHash(text)}  ${file}`);
    } catch (e) {
      console.error(`${file}: ${message(e)}`);
      clean = false;
    }
  }
  if (!clean) throw new Problems();
}

async function keys([action, ...rest]) {
  if (action !== "new") throw new Failed(`unknown keys command ${action ?? ""}; use new`);
  const { values } = parse(rest, { publisher: { type: "string" }, id: { type: "string" }, output: { type: "string", short: "o" } }, 0);
  if (!values.publisher) throw new Failed("keys new needs --publisher <domain>");
  if (!values.id) throw new Failed("keys new needs --id <key-id>");
  if (!values.output) throw new Failed("keys new needs -o <key-file>");
  if (values.output === "-") throw new Failed("-o -: the secret key goes to a file, not stdout");
  let generated;
  try {
    generated = legible.generateKey(values.publisher, values.id);
  } catch (e) {
    throw new Failed(message(e));
  }
  const { secretKey, keySetEntry } = generated;
  try {
    let fd;
    try {
      // Created private: never written and then restricted. An existing file is refused.
      fd = openSync(values.output, "wx", 0o600);
    } catch (e) {
      throw new Failed(`${values.output}: ${message(e)}`);
    }
    try {
      writeSync(fd, secretKey);
    } catch (e) {
      closeSync(fd);
      fd = undefined;
      try {
        unlinkSync(values.output);
      } catch {}
      throw new Failed(`${values.output}: ${message(e)}`);
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  } finally {
    secretKey.fill(0);
  }
  console.log(JSON.stringify(keySetEntry, null, 2));
}

// ---- Arguments and files ----

function parse(args, options, count) {
  let parsed;
  try {
    parsed = parseArgs({ args, options, allowPositionals: true, strict: true });
  } catch (e) {
    throw new Failed(message(e));
  }
  if (count >= 0 && parsed.positionals.length !== count) {
    throw new Failed(`expected ${count} file${count === 1 ? "" : "s"}, got ${parsed.positionals.length}; see legible --help`);
  }
  return parsed;
}

function message(e) {
  return e instanceof Error ? e.message : String(e);
}

function readInput(file) {
  try {
    return file === "-" ? readFileSync(0) : readFileSync(file);
  } catch (e) {
    throw new Failed(`${file}: ${message(e)}`);
  }
}

function readJson(file) {
  const text = readInput(file).toString("utf8");
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Failed(`${file}: not JSON: ${message(e)}`);
  }
}

function writeOutput(file, bytes) {
  try {
    if (file === "-") process.stdout.write(bytes);
    else writeFileSync(file, bytes);
  } catch (e) {
    throw new Failed(`${file}: ${message(e)}`);
  }
}

/** A file, or every regular file under a directory, sorted. Symbolic links are skipped. */
function collect(path) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch (e) {
    throw new Failed(`${path}: ${message(e)}`);
  }
  if (stat.isDirectory()) {
    return readdirSync(path).sort().flatMap((entry) => collect(join(path, entry)));
  }
  return stat.isFile() ? [path] : [];
}

function nameFor(file, values) {
  if (values.name) return values.name;
  let name = basename(file);
  for (const suffix of [".yaml", ".yml", ".json"]) if (name.endsWith(suffix)) name = name.slice(0, -suffix.length);
  return name.endsWith(".schema") ? name.slice(0, -".schema".length) : name;
}

function expandOptions(values) {
  const options = {};
  for (const key of ["base", "common", "location"]) if (values[key] !== undefined) options[key] = values[key];
  return options;
}

/** A schema from a short-form (.yaml, .yml) or JSON file, expanded. */
function loadSchema(file, values) {
  if (!/\.ya?ml$/.test(file)) return readJson(file);
  const result = legible.expand(readInput(file).toString("utf8"), nameFor(file, values), expandOptions(values));
  if (result.ok) return result.body;
  for (const p of result.problems) console.error(p.path ? `${file}:${p.line}: ${p.path}: ${p.message}` : `${file}:${p.line}: ${p.message}`);
  throw new Problems();
}

// ---- Validation ----

/** The schema for a record: the one whose $type and version consts match. */
function schemaFor(schemas, record) {
  return schemas.find(
    (s) => s?.properties?.$type?.const === record?.$type && s?.properties?.version?.const === record?.version,
  );
}

/**
 * The records a file holds, each with where it is: a .json file holds one, a
 * .ndjson file one per line (blank lines skipped). A record that isn't JSON
 * comes back with its error, so the records after it are still checked; a file
 * that can't be read stops the tool.
 */
function records(file) {
  const parse = (at, text) => {
    try {
      return { at, record: JSON.parse(text) };
    } catch (e) {
      return { at, error: message(e) };
    }
  };
  const text = readInput(file).toString("utf8");
  if (!/\.ndjson$/i.test(file)) return [parse(file, text)];
  return text.split("\n").flatMap((line, i) => (line.trim() ? [parse(`${file}: line ${i + 1}`, line)] : []));
}

async function validate(schemas, files) {
  const { default: Ajv2020 } = await import("ajv/dist/2020.js");
  const { default: addFormats } = await import("ajv-formats");
  // Nothing is fetched: references resolve only to the schemas given and common.
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);
  ajv.addKeyword({ keyword: "ref", schemaType: ["string", "array"] });
  const common = legible.commonSchema();
  ajv.addSchema(common);
  for (const schema of schemas) {
    if (typeof schema.$id !== "string") throw new Failed("a schema used for validation needs an $id");
    if (schema.$id === common.$id) continue;
    try {
      ajv.addSchema(schema);
    } catch (e) {
      throw new Failed(`${schema.$id}: ${message(e)}`);
    }
  }
  let ok = true;
  for (const { at, record, error } of files.flatMap(records)) {
    if (error) {
      ok = false;
      console.log(`${at}: not JSON: ${error}`);
      continue;
    }
    const schema = schemaFor([...schemas, common], record);
    if (!schema) {
      ok = false;
      console.log(`${at}: no schema given for ${JSON.stringify(record?.$type ?? "no $type")} version ${JSON.stringify(record?.version ?? "no version")} (common is ${common.$id})`);
      continue;
    }
    let check;
    try {
      check = ajv.getSchema(schema.$id);
    } catch (e) {
      throw new Failed(`${schema.$id}: ${message(e)}`);
    }
    if (!check(record)) {
      ok = false;
      for (const error of check.errors) console.log(`${at}: ${error.instancePath || "/"}: ${error.message}`);
    }
  }
  if (!ok) throw new Problems();
}

// ---- Bundles ----

const AGE_BINARY = Buffer.from("age-encryption.org/");
const AGE_ARMOR = Buffer.from("-----BEGIN AGE ENCRYPTED FILE-----");

function startsWith(bytes, prefix) {
  return bytes.length >= prefix.length && Buffer.from(bytes.subarray(0, prefix.length)).equals(prefix);
}

/** A new passphrase: 25 characters from a 31-character alphabet (about 124 bits), in groups of five. */
function newPassphrase() {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const groups = [];
  for (let g = 0; g < 5; g++) {
    let group = "";
    for (let i = 0; i < 5; i++) group += alphabet[randomInt(alphabet.length)];
    groups.push(group);
  }
  return groups.join("-");
}

async function encrypt(bytes, values) {
  const age = await import("age-encryption");
  const encrypter = new age.Encrypter();
  if (values.passphrase) {
    if (values.recipient?.length) throw new Failed("use either --passphrase or --recipient, not both");
    let passphrase = process.env.LEGIBLE_PASSPHRASE;
    if (!passphrase) {
      passphrase = newPassphrase();
      console.error(`passphrase: ${passphrase}`);
      console.error("Send it by a different channel than the bundle.");
    }
    encrypter.setPassphrase(passphrase);
  }
  for (const recipient of values.recipient ?? []) {
    try {
      encrypter.addRecipient(recipient);
    } catch (e) {
      throw new Failed(`${recipient}: ${message(e)}`);
    }
  }
  const encrypted = await encrypter.encrypt(bytes);
  return values.armor ? Buffer.from(age.armor.encode(encrypted)) : encrypted;
}

async function decrypt(bytes, values, file) {
  const age = await import("age-encryption");
  let ciphertext = bytes;
  if (startsWith(bytes, AGE_ARMOR)) {
    try {
      ciphertext = age.armor.decode(Buffer.from(bytes).toString("utf8"));
    } catch (e) {
      throw new Failed(`${file}: ${message(e)}`);
    }
  }
  const decrypter = new age.Decrypter();
  const identities = (values.identity ?? []).flatMap((path) =>
    readInput(path)
      .toString("utf8")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.startsWith("AGE-SECRET-KEY-")),
  );
  for (const identity of identities) decrypter.addIdentity(identity);
  if (!identities.length) {
    const passphrase = process.env.LEGIBLE_PASSPHRASE || (await prompt(`Passphrase for ${file}: `));
    decrypter.addPassphrase(passphrase);
  }
  try {
    return await decrypter.decrypt(ciphertext);
  } catch (e) {
    throw new Failed(`${file}: couldn't decrypt: ${message(e)}`);
  }
}

/** Reads a line from the terminal without echoing it. */
function prompt(question) {
  const input = process.stdin;
  if (!input.isTTY) {
    throw new Failed("the bundle is encrypted; set LEGIBLE_PASSPHRASE, or give -i with an age identity");
  }
  return new Promise((done, fail) => {
    process.stderr.write(question);
    input.setRawMode(true);
    input.resume();
    let answer = "";
    const finish = (error) => {
      input.setRawMode(false);
      input.pause();
      input.off("data", onData);
      process.stderr.write("\n");
      if (error) fail(error);
      else done(answer);
    };
    const onData = (chunk) => {
      for (const char of chunk.toString("utf8")) {
        if (char === "\r" || char === "\n") return finish();
        if (char === "\u0003") return finish(new Failed("cancelled"));
        if (char === "\u007f" || char === "\b") answer = answer.slice(0, -1);
        else answer += char;
      }
    };
    input.on("data", onData);
  });
}

async function openBundle(file, values) {
  if (file === "-" && (values.identity ?? []).includes("-")) {
    throw new Failed("-i -: the bundle is already read from stdin; give the identity as a file");
  }
  let bytes = readInput(file);
  if (startsWith(bytes, AGE_BINARY) || startsWith(bytes, AGE_ARMOR)) bytes = await decrypt(bytes, values, file);
  try {
    return legible.Bundle.open(bytes);
  } catch (e) {
    for (const line of message(e).split("\n")) console.log(`${file}: ${line}`);
    throw new Problems();
  }
}

/** `<publisher>/<id>=<public_key>`: a quick look here, for a clear message, then the
 * library's own check (the one the Rust tool uses), which has the final word. */
function parsePin(text) {
  const shape = "expected <publisher>/<id>=<public_key>, such as acme.example/2026-11=<base64url>";
  const eq = text.indexOf("=");
  const slash = eq < 0 ? -1 : text.slice(0, eq).indexOf("/");
  if (eq < 0 || slash < 0) throw new Failed(`--pin ${text}: ${shape}`);
  const publisher = text.slice(0, slash);
  const id = text.slice(slash + 1, eq);
  const publicKey = text.slice(eq + 1);
  if (publisher.length > 253 || !/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+([0-9]*[a-z]([a-z0-9-]*[a-z0-9])?|[0-9]+-[a-z0-9-]*[a-z0-9])$/.test(publisher)) {
    throw new Failed(`--pin ${text}: ${JSON.stringify(publisher)} is not a publisher: ${shape}`);
  }
  if (!/^[a-z0-9][a-z0-9.-]{0,63}$/.test(id)) {
    throw new Failed(`--pin ${text}: ${JSON.stringify(id)} is not a key id: ${shape}`);
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(publicKey)) {
    throw new Failed(`--pin ${text}: the public key isn't 32 bytes of base64url without padding`);
  }
  try {
    return legible.parsePin(text);
  } catch (e) {
    throw new Failed(`--pin ${text}: ${message(e)}`);
  }
}

/** Each --key-set file, read and checked on its own, so an error names its path. */
function keySetsFrom(paths) {
  const seen = new Map();
  return paths.map((path) => {
    const bytes = new Uint8Array(readInput(path));
    let publisher;
    try {
      publisher = legible.checkKeySet(bytes);
    } catch (e) {
      throw new Failed(`${path}: ${message(e)}`);
    }
    if (seen.has(publisher)) throw new Failed(`${path}: a second key set for ${publisher} (the first is ${seen.get(publisher)})`);
    seen.set(publisher, path);
    return bytes;
  });
}

/** The keys given with --pin and --key-set, as verifySignature takes them. */
function trustFrom(values) {
  const pins = (values.pin ?? []).map(parsePin);
  const keySets = keySetsFrom(values["key-set"] ?? []);
  return { pins, keySets, given: pins.length + keySets.length > 0 };
}

/** The signature line `bundle verify` prints, and whether it is a problem. */
function signatureLine(opened, trust) {
  try {
    if (!trust.given) {
      const by = opened.signedBy();
      return by
        ? [`signature: unverified (signed by ${by.publisher} ${by.key}; no trusted keys given)`, false]
        : ["signature: unverified", false];
    }
    const result = opened.verifySignature({ pins: trust.pins, keySets: trust.keySets });
    return result.status === "verified"
      ? [`signature: verified (${result.publisher} ${result.key})`, false]
      : ["signature: unverified", false];
  } catch (e) {
    return [`signature: ${message(e)}`, true];
  }
}

function verify(file, opened, values) {
  const schemas = (values.schema ?? []).map((s) => loadSchema(s, values));
  const trust = trustFrom(values);
  const report = opened.verify(schemas);
  for (const problem of report.problems) console.log(`${file}: ${problem}`);
  for (const kind of report.uncheckedTypes) console.error(`${file}: no schema given for ${kind}; its references weren't checked`);
  const [line, bad] = signatureLine(opened, trust);
  console.log(line);
  if (report.problems.length || bad) throw new Problems();
}

/** Writes a verified bundle into a new or empty directory, never over a file. */
function unpack(opened, directory) {
  let entries = [];
  try {
    entries = readdirSync(directory);
  } catch (e) {
    if (e.code !== "ENOENT") throw new Failed(`${directory}: ${message(e)}`);
  }
  if (entries.length) throw new Failed(`${directory}: not empty; unpack into a new or empty directory`);
  const root = resolve(directory);
  // The manifest and signature exactly as stored: a signature covers these bytes.
  const files = [["manifest.json", opened.manifestBytes()]];
  const signature = opened.signature();
  if (signature !== undefined) files.push(["manifest.sig", signature]);
  for (const path of opened.paths()) files.push([path, opened.file(path)]);
  for (const [path, bytes] of files) {
    const target = resolve(root, path);
    const inside = relative(root, target);
    // Bundle.open has refused unsafe paths already; this is a second lock.
    if (!inside || inside.startsWith(`..${sep}`) || inside === ".." || isAbsolute(inside)) {
      throw new Failed(`${path}: not inside ${directory}`);
    }
    try {
      mkdirSync(dirname(target), { recursive: true });
      const fd = openSync(target, "wx");
      try {
        writeSync(fd, bytes);
      } finally {
        closeSync(fd);
      }
    } catch (e) {
      throw new Failed(`${target}: ${message(e)}`);
    }
  }
}

// ---- Run ----

main(process.argv.slice(2)).catch((e) => {
  if (!(e instanceof Problems)) console.error(`legible: ${e instanceof Failed ? e.message : (e?.stack ?? e)}`);
  process.exitCode = e instanceof Problems ? 1 : 2;
});
