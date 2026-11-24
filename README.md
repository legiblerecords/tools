# Legible Records tools

Tools for [Legible Records](https://github.com/legiblerecords/spec): legible, portable, pragmatic security records.

Status: early. Nothing here is released yet.

## What's here

| Path | What it is |
|---|---|
| [crates/legible](crates/legible) | `legible`, the command-line tool |
| [crates/legible-records](crates/legible-records) | The Rust library the tool is built on |
| [crates/legible-records-wasm](crates/legible-records-wasm) and [packages/legible](packages/legible) | `@legiblerecords/legible`, the same code as WebAssembly for JavaScript |

## The command-line tool

```sh
cargo install --git https://github.com/legiblerecords/tools legible
```

| Command | Does |
|---|---|
| `legible expand <schema.yaml>` | Expands a short-form schema to JSON Schema |
| `legible generate <schema.json>` | Writes a JSON Schema back as canonical short form |
| `legible lint <schema>` | Checks a published type against the published subset |
| `legible check-compat <old> <new>` | Lists changes that would break readers or writers of the old version |
| `legible validate -s <schema> <record.json>…` | Validates records against their types, chosen by `$type` and `version` |
| `legible bundle pack <file or dir>… -o <bundle.zip>` | Packs records and attachments into a bundle |
| `legible bundle verify <bundle.zip>` | Checks a bundle's hashes, file list and references |
| `legible bundle unpack <bundle.zip> -d <dir>` | Verifies a bundle (as `verify` does), then writes its files into a new or empty directory |
| `legible keys new --publisher <domain> --id <id> -o <key.json>` | Makes a signing key: the secret goes to a new file (mode 0600, never overwritten), the key-set entry is printed |
| `legible keys sign <keys.json> -k <key.json> -o <keys.sig>` | Signs a key set as stored, endorsing it |
| `legible bundle sign <bundle.zip> -k <key.json> -o <signed.zip>` | Signs a bundle's manifest as stored |

For a published type, give the base of its `$id` with `--base`, such as `--base https://monorail.tech/schemas/`. Shared names such as `date` then point at `org.legiblerecords.common`.

```sh
legible expand appetite.yaml --base https://monorail.tech/schemas/ > appetite.json
legible lint appetite.json --base https://monorail.tech/schemas/
legible validate -s appetite.json decision.json
```

### Signing

```sh
legible keys new --publisher acme.example --id 2026-11 -o acme-2026-11.key.json   # prints the entry for keys.json
legible bundle sign evidence.zip -k acme-2026-11.key.json -o evidence.signed.zip
legible bundle verify evidence.signed.zip --pin acme.example/2026-11=<public_key>
```

`bundle verify` and `bundle unpack` take `--pin <publisher>/<id>=<public_key>` and `--key-set <keys.json>`, each repeatable. A key set is read from a file; nothing is fetched. `verify` prints one line about the signature: `signature: verified (<publisher> <key>)`, `signature: unverified`, or the outcome code of a signature that failed, such as `signature: unknown_key` (exit 1).

Exit 0 from `verify` doesn't mean a signature was checked. A signed bundle given no `--pin` or `--key-set` prints `signature: unverified (signed by <publisher> <key>; no trusted keys given)` and exits 0; only `verified` means it was checked. Keep the secret key file private: `keys new` creates it readable by you alone and prints only the public entry.

`keys sign` signs a key set with a key already in the set readers hold, which endorses the new set (for example one that adds the next key).

Exit status is 0 when everything passes, 1 when the input has problems, and 2 when the tool couldn't run. `validate` never fetches anything: every schema it needs is given with `-s`, and `org.legiblerecords.common` version 1 is built in.

### Bundles

`bundle pack` treats a `.json` file with `$type` and `version` as a record, and stores it at `records/<kind>/<id>.json`; anything else is an attachment, stored by its SHA-256, and the reference to put in a record is printed to stderr. Give the records' schemas with `-s` and `kind` is each type's `title`, and `verify` checks references between records as well as to attachments. The same files always pack to the same bytes.

A bundle sent by email or another transport you don't trust should be encrypted. The npm package's `legible` does that itself, with a passphrase or age keys:

```sh
npx @legiblerecords/legible bundle pack evidence/ -o evidence.zip.age --passphrase   # prints a new passphrase
npx @legiblerecords/legible bundle unpack evidence.zip.age -d evidence               # prompts for it
```

With this tool, pipe through [age](https://age-encryption.org), which can also encrypt to SSH keys:

```sh
legible bundle pack evidence/ -o - | age -R ~/.ssh/id_ed25519.pub > evidence.zip.age
age -d -i ~/.ssh/id_ed25519 evidence.zip.age > evidence.zip && legible bundle unpack evidence.zip -d evidence
```

All of them implement the [spec](https://github.com/legiblerecords/spec), and are tested against its vectors: `crates/legible-records/tests/vectors/` holds a copy, and `SOURCE` says which spec commit it came from.

### Feeds in S3

A feed in an S3-compatible bucket is read with presigned GETs. The reader's access key needs `s3:ListBucket` on the feed's prefix as well as `s3:GetObject`: a reader asks for files that may not exist (`feed.json.age` beside `feed.json`, and `feed.sig`), and S3 answers `404` for a missing object only to a key that may list the bucket. To any other key it answers `403`, which the reader reports as an error.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
