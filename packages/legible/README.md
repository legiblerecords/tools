# @legiblerecords/legible

[Legible Records](https://github.com/legiblerecords/spec) in JavaScript: expand short-form schemas to JSON Schema and generate them back, lint published types, check that a new version of a type is compatible with the last, and pack and verify bundles. It's the same Rust code as the `legible` command-line tool, compiled to WebAssembly, and it comes with that tool for Node, which can also encrypt bundles with [age](https://age-encryption.org).

Status: early, not yet published.

## The command

```sh
npx @legiblerecords/legible@0.1.0 --help
```

It has the Rust tool's commands (`expand`, `generate`, `lint`, `check-compat`, `validate`, and `bundle pack`, `verify`, `unpack` and `sign`, and `keys new`), and encrypts bundles for sending over email and other transports you don't trust:

```sh
# A new passphrase, printed to stderr: send it by a different channel than the bundle.
legible bundle pack evidence/ -o evidence.zip.age --passphrase
# Or your own, from the environment, never from the command line.
LEGIBLE_PASSPHRASE=... legible bundle pack evidence/ -o evidence.zip.age --passphrase --armor
# Or to age public keys.
legible bundle pack evidence/ -o evidence.zip.age -r age1...

# Decrypting is automatic: LEGIBLE_PASSPHRASE, a prompt, or -i with an age identity file.
legible bundle unpack evidence.zip.age -d evidence
legible bundle verify evidence.zip.age -i key.txt -s control.yaml --base https://monorail.tech/schemas/
```

`unpack` verifies first and writes nothing from a bundle that fails, only into a new or empty directory. Encrypting to SSH keys needs the [age](https://age-encryption.org) command: `legible bundle pack evidence/ -o - | age -R ~/.ssh/id_ed25519.pub`.

## Signing

A publisher signs a bundle's manifest with an ed25519 key, and readers check the signature against keys they trust. The output and exit codes match the Rust tool's.

```sh
# The secret key goes to a new file (mode 0600, an existing file is refused); the entry to add to your keys.json is printed.
legible keys new --publisher acme.example --id 2026-11 -o key.json
legible bundle sign evidence.zip -k key.json -o evidence.signed.zip

# Trust a key (repeat for several), or a publisher's keys.json.
legible bundle verify evidence.signed.zip --pin acme.example/2026-11=<public_key>
legible bundle unpack evidence.signed.zip -d evidence --key-set keys.json
```

`bundle verify` prints `signature: verified (<publisher> <key>)`, `signature: unverified` for an unsigned bundle, or `signature: unverified (signed by <publisher> <key>; no trusted keys given)` when a signed bundle is checked with no `--pin` or `--key-set`. A signature that fails prints its code (`unknown_key`, `bad_signature`, `revoked_key`, ...) and exits 1. A malformed `--pin` or a key set that doesn't parse exits 2. Exit 0 means a signature was checked only when the line says `verified`.

## Node

```js
import { expand, lint } from "@legiblerecords/legible";

const result = expand(text, "risk-appetite", { base: "https://monorail.tech/schemas/" });
if (result.ok) {
  console.log(lint(result.body)); // [] when it's within the published subset
} else {
  for (const p of result.problems) console.error(`${p.line}: ${p.path}: ${p.message}`);
}
```

## Browsers and bundlers

The browser build needs its WebAssembly loaded once before use:

```js
import init, { expand } from "@legiblerecords/legible";

await init();
const result = expand(text, "risk-appetite", { base: "https://monorail.tech/schemas/" });
```

## Functions

| Function | Returns |
|---|---|
| `expand(text, name, options?)` | `{ ok: true, body }` or `{ ok: false, problems: [{ line, path, message }] }` |
| `generate(body, name, options?)` | the canonical short form, as a string |
| `normalize(body)` | the schema's normal form |
| `lint(schema)` | `[{ pointer, message }]`, empty when it passes |
| `checkCompat(old, new)` | `[{ pointer, message }]`, empty when compatible |
| `parseYaml(text)` | `{ ok: true, value }` or `{ ok: false, error: { reason, line, col, message } }` |
| `commonSchema()` | `org.legiblerecords.common` version 1 |
| `new BundleBuilder()` | `.add(name, bytes)` each file, then `.finish(schemas?, producedBy?)`, which returns a `PackedBundle` with `.zip()`, `.manifest()` and `.attachments()`, or throws with every problem, one per line |
| `Bundle.open(bytes)` | a `Bundle`, with `.manifest()`, `.paths()`, `.file(path)` and `.verify(schemas?)` → `{ problems, uncheckedTypes }`; throws for an unsafe or oversized zip |
| `bundle.verifySignature({ pins?, keySets?, expectedPublisher? })` | `{ status: "verified", publisher, key }` or `{ status: "unverified" }`. `pins` are `[{ publisher, id, publicKey }]` (base64url), `keySets` are `Uint8Array`s of a publisher's keys.json as stored. Throws an `Error` whose `message` is the outcome code, such as `unknown_key` or `bad_signature` |
| `bundle.signedBy()` | `{ publisher, key }` the manifest claims, unchecked, or `undefined` if unsigned |
| `generateKey(publisher, id)` | `{ secretKey: Uint8Array, keySetEntry }`: the secret key file's bytes, which you keep private, and the entry for your keys.json |
| `signBundle(zip, secretKey)` | the bundle's bytes with `manifest.sig` added; throws if it has problems or is already signed |

The bundle classes hold WebAssembly memory: call `.free()` when you're done with one.

`options` is `{ base?, common?, location? }`. Giving `base` marks a published type, and points shared names such as `date` at `org.legiblerecords.common`.

## Validating records

The functions don't validate records: expanded schemas are standard JSON Schema 2020-12, so use a validator such as [Ajv](https://ajv.js.org) (with `ajv/dist/2020` and `ajv-formats`), adding `commonSchema()` and your types to it. That's what `legible validate` does.

## License

Apache License 2.0.
