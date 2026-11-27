# Legible Records tools

Tools for [Legible Records](https://github.com/legiblerecords/spec): legible, portable, pragmatic security records.

Status: early. The first release is [v0.1.0](https://github.com/legiblerecords/tools/releases/tag/v0.1.0); expect changes before 1.0.

## What's here

| Path | What it is |
|---|---|
| [crates/legible](crates/legible) | `legible`, the command-line tool |
| [crates/legible-records](crates/legible-records) | The Rust library the tool is built on |
| [crates/legible-records-wasm](crates/legible-records-wasm) and [packages/legible](packages/legible) | `@legiblerecords/legible`, the same code as WebAssembly for JavaScript |

## The command-line tool

Download a build for your platform from the [releases](https://github.com/legiblerecords/tools/releases): static Linux (x86_64, aarch64), macOS (Apple silicon, Intel) and Windows (x86_64), with `SHA256SUMS` and build provenance. For example, on Linux x86_64:

```sh
curl -fsSLO https://github.com/legiblerecords/tools/releases/latest/download/legible-x86_64-unknown-linux-musl.tar.gz
curl -fsSL https://github.com/legiblerecords/tools/releases/latest/download/SHA256SUMS | sha256sum -c --ignore-missing
tar -xzf legible-x86_64-unknown-linux-musl.tar.gz && ./legible-x86_64-unknown-linux-musl/legible --version
```

The other archives are `legible-aarch64-unknown-linux-musl.tar.gz`, `legible-aarch64-apple-darwin.tar.gz`, `legible-x86_64-apple-darwin.tar.gz` and `legible-x86_64-pc-windows-msvc.zip`. `gh attestation verify <archive> --repo legiblerecords/tools` checks that an archive was built by this repository's release workflow.

Or build it from source, with Rust 1.89 or later:

```sh
cargo install --git https://github.com/legiblerecords/tools legible
```

A release is made by pushing a tag `v<version>` matching the workspace version in `Cargo.toml` and the version in `packages/legible/package.json`; [release.yml](.github/workflows/release.yml) builds and publishes the GitHub release, then stages `@legiblerecords/legible` on npm, where a maintainer approves it with 2FA before it's public.

| Command | Does |
|---|---|
| `legible expand <schema.yaml>` | Expands a short-form schema to JSON Schema |
| `legible generate <schema.json>` | Writes a JSON Schema back as canonical short form |
| `legible lint <schema>` | Checks a published type against the published subset |
| `legible check-compat <old> <new>` | Lists changes that would break readers or writers of the old version |
| `legible validate -s <schema> <record.json>…` | Validates records against their types, chosen by `$type` and `version`; a broken rule is reported by rule, with its own message |
| `legible record hash <record.json>…` | Prints each record's content hash, the SHA-256 of its canonical line without `produced_by` and `source`: what an external reference's `sha256` pins |
| `legible bundle pack <file or dir>… -o <bundle.zip>` | Packs records and attachments into a bundle |
| `legible bundle verify <bundle> [-i <identity>] [--pin …] [--key-set …]` | Checks a bundle's hashes, file list, references and signature; decrypts an encrypted one with `-i` |
| `legible bundle unpack <bundle> -d <dir> [-i <identity>] [--pin …] [--key-set …]` | Verifies a bundle (as `verify` does), then writes its files, with `manifest.json` and `manifest.sig` exactly as stored, into a new or empty directory |
| `legible keys new --publisher <domain> --id <id> -o <key.json>` | Makes a signing key: the secret goes to a new file (mode 0600, never overwritten), the key-set entry is printed |
| `legible keys sign <keys.json> -k <key.json> -o <keys.sig>` | Signs a key set as stored, endorsing it |
| `legible bundle sign <bundle.zip> -k <key.json> -o <signed.zip>` | Signs a bundle's manifest as stored |
| `legible feed publish <dir> --feed <id> --stream <id> …` | Packs records into a stream of a feed in a directory: the bundle, then `feed.json` (or `.age`) and `feed.sig` |
| `legible feed check <connection.json>` | Polls a feed and reports each stream's outcome; stateless, so it keeps and delivers nothing |
| `legible feed pull <connection.json> --state <dir> --out <dir>` | Polls a feed, writes each accepted bundle to `<out>/<stream>/<published_at>-<hash>.zip`, and keeps the reader state |

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

`bundle verify` and `bundle unpack` take `--pin <publisher>/<id>=<public_key>` and `--key-set <keys.json>`, each repeatable. A key set is read from a file; nothing is fetched. A pin and a key set that disagree about a key id make that id untrusted (`unknown_key`), and so does a pin whose public key a key set lists under another id (one key has one name: fix the pin); a key a key set revokes is revoked even if pinned. A `--pin` or `--key-set` that can't be read is exit 2, naming it. Both print one line about the signature: `signature: verified (<publisher> <key>)`, `signature: unverified`, or the outcome code of a signature that failed, such as `signature: unknown_key` (exit 1). An encrypted bundle is decrypted with `-i <age identity file>`; the bundle and the identity can't both be `-` (stdin).

Exit 0 from `verify` doesn't mean a signature was checked. A signed bundle given no `--pin` or `--key-set` prints `signature: unverified (signed by <publisher> <key>; no trusted keys given)` and exits 0; only `verified` means it was checked. Keep the secret key file private: `keys new` creates it readable by you alone and prints only the public entry.

`keys sign` signs a key set with a key already in the set readers hold, which endorses the new set (for example one that adds the next key). It warns when the key isn't in the set it signs.

Exit status is 0 when everything passes, 1 when the input has problems, and 2 when the tool couldn't run. `validate` never fetches anything: every schema it needs is given with `-s`, and `org.legiblerecords.common` version 1 is built in.

`validate` prints each failure as `<file>: <pointer>: <message>`. A type's own keywords fail with the validator's message; a rule (an `allOf` member with `x-rule`, written under `rules` in the short form) fails as one line with the rule's message and the pointer of the object it sits on, such as `/approvals/1: needs exactly one of at and on` or `/: opened_on 2026-02-01 isn't before closed_on 2026-01-31`, after the type's own failures. A rule that a validator can also reach through a union, such as `t.window | string`, stays in the type's own keywords and fails with the validator's message.

### Bundles

`bundle pack` treats a `.json` file with `$type` and `version` as a record, and stores it at `records/<kind>/<id>.json`; anything else is an attachment, stored by its SHA-256, and the reference to put in a record is printed to stderr. Give the records' schemas with `-s` and `kind` is each type's `title`, and `verify` checks references between records as well as to attachments. The same files always pack to the same bytes.

Many records of one type can travel as one **record set**, `records/<kind>.ndjson`: one complete record per line, compact, keys sorted, lines sorted by `id` ([spec § Record sets](https://github.com/legiblerecords/spec/blob/main/spec/records.md#record-sets)). `bundle pack` writes a kind as a set when it has more than 1,000 records (across its versions), or when you ask with `--set <kind>` (repeatable); `--no-sets` writes every record as its own file. A `.ndjson` input is checked and packed as the set it is. `verify` checks every line, and names the file and line of the first problem; `unpack` writes a set byte for byte. In the library, `record_set::Reader` reads a set as a stream, one record at a time, and its `finish` says whether the whole file matched its manifest entry.

A bundle sent by email or another transport you don't trust should be encrypted. The npm package's `legible` does that itself, with a passphrase or age keys:

```sh
npx @legiblerecords/legible bundle pack evidence/ -o evidence.zip.age --passphrase   # prints a new passphrase
npx @legiblerecords/legible bundle unpack evidence.zip.age -d evidence               # prompts for it
```

With this tool, encrypt by piping through [age](https://age-encryption.org) to an age recipient, and decrypt with `-i`, which `verify` and `unpack` take directly:

```sh
age-keygen -o reader.age.txt   # prints the recipient, age1...
legible bundle pack evidence/ -o - | age -r age1... > evidence.zip.age
legible bundle unpack evidence.zip.age -i reader.age.txt -d evidence
```

All of them implement the [spec](https://github.com/legiblerecords/spec), and are tested against its vectors: `crates/legible-records/tests/vectors/` holds a copy, and `SOURCE` says which spec commit it came from.

### Feeds

A feed is a directory of files served at a base URL (or kept in an S3 bucket): `feed.json` (or `feed.json.age` when encrypted, never both), its `feed.sig`, and `bundles/<sha256>.zip[.age]`. The [spec](https://github.com/legiblerecords/spec) (`spec/feeds.md`) defines them.

**Publishing.** `feed publish` writes into a directory laid out as the feed's base URL, and never deploys: getting the directory to the web or a bucket is yours.

```sh
legible feed publish ./site/track --feed acme.example/track --audience "Monorail, for Track" \
  --stream policy-acknowledgments --title "Policy acknowledgments" -k acme-2026-11.key.json acks/
legible feed publish ./site/track --feed acme.example/track --audience "Monorail, for Track" \
  --stream policy-acknowledgments --title x --withdraw -k acme-2026-11.key.json
```

It packs the inputs into a bundle signed with `-k`, then writes the bundle, `feed.json` and `feed.sig` in that order, each by temporary file and rename. Give `-r <age recipient>` to encrypt the bundle and the index (an encrypted feed needs `-r` on every publish, and `-i <identity>` to read its index). Bundles no stream points at any more are deleted only with `--state <file>`, after `--grace` hours (default 24, at least 1); the state file also keeps each stream's last `published_at` and the index's last `updated_at`, so a stream withdrawn and published again, or an index rebuilt, never goes back in time. A `--state` file that can't be read stops the publish before anything is written.

With `-k`, `feed publish` builds on the existing index only if its `feed.sig` is that key's signature over it: an index that whoever can write the directory has changed is refused, as is one with no `feed.sig`. `--rebuild` starts the index again from the stream on the command line only, dropping the others, and says so; the dropped streams' bundles are noted for deletion after the grace (with `--state`), and the new index is dated after the one it replaces, which `--state` also keeps, so readers don't refuse it as `stale_feed`. **After rotating to a new key**, the existing `feed.sig` is the old key's: give the old public key with `--previous-key <publisher>/<id>=<public_key>` (written as `--approve` and `--pin` take it; a secret key file is refused) on the first publish with the new key, and every stream is kept. If the old key was revoked, its thief may have changed the index, so use `--rebuild` instead. Keep the publish directory where the storage the feed is served from can't write to it, such as the machine or CI job that publishes, and copy it out from there: the publisher reads its own index back, and the signature check is what stops a changed one being signed again.

**Reading.** A connection file says where a feed is, how to authenticate and which keys to trust. It names environment variables, never secrets:

```json
{
  "$type": "org.legiblerecords.feed-connection",
  "version": 1,
  "feed": "acme.example/track",
  "location": {"kind": "https", "url": "https://feeds.acme.example/track/"},
  "auth": {"method": "bearer", "token_env": "ACME_FEED_TOKEN"},
  "keys": [{"publisher": "acme.example", "id": "2026-11", "alg": "ed25519", "public_key": "<base64url>"}],
  "age_identity_env": "ACME_AGE_IDENTITY"
}
```

```sh
ACME_FEED_TOKEN=... legible feed check connection.json
ACME_FEED_TOKEN=... legible feed pull connection.json --state ~/.legible/state --out ~/records
```

Both fetch the publisher's key set from `https://<publisher>/.well-known/legible-records/` on every poll, before the index, so a rotation or a revocation reaches them even when `feed.json` hasn't changed. A key the connection file pins whose public key the publisher's key set lists under another id isn't trusted: what names the pinned id is `unknown_key` until the connection file is fixed. They print one line per stream: `<id>: accepted (verified <publisher> <key>)`, `accepted (unverified)`, `unchanged`, `withdrawn`, the outcome code of a refusal (such as `replay`, `bad_signature`, or `revoked_key` for a stream cleared because the held key set revoked the key that signed it, or for a bundle or index signed by a revoked key), or `failed: <message>`. A refused index prints `index: <code>`, and for `bad_feed` the reason on stderr. A refused key set prints `keys: <code>` (`bad_key_set`, `key_set_rollback` or `bad_endorsement`). A publisher's key set can add a key nobody endorsed; the key is not trusted until you approve it: the poll prints `keys: needs_approval` and `pending key: --approve <publisher>/<id>=<public_key>`. Give that argument (repeatable) to the next `feed pull`, which keeps it in the state.

In the library (feature `net`), `HttpsKeySource::loopback(origin)` reads every publisher's key set from a loopback `origin` such as `http://127.0.0.1:8080` instead of `https://<publisher>`. It is for a reader on the publisher's own machine, such as an outpost's collector reading the key set from the node's own server while it pins the signer's key; any non-loopback origin is an error. It was `with_base`, which stays as a deprecated alias.

`feed check` is stateless: nothing is written, its only anchors are the connection file's pins, and the history checks (`replay`, `stale_feed`) need a state, so use it to see whether a feed and its signatures are good, not as a reader. `feed pull` keeps `<state>/<feed id with / as __>.json`, written by temporary file and rename and only when something changed. A refused or unreadable index leaves the rest of it untouched, but the key steps run on every poll: an accepted key set is kept, and streams a key revoked by the held key set signed are cleared, whatever happens to the index. A cleared stream loses its hash and signer, so it is fetched and checked again next poll, but keeps its `published_at`, and the index keeps its `updated_at`: they stay as replay floors, so a revocation never lets old signed content back in. A revocation in a key set that isn't held (one waiting for approval, or refused as `bad_endorsement` or `key_set_rollback`) refuses what that key signed on that poll, and changes nothing in the state, since anyone who controls the publisher's server can serve one. The state records who signed each stream's bundle and the index; a state file from an earlier version, without them, is still read, as if everything in it was unsigned, so a revocation clears those streams only once they have been accepted again. The state holds what the spec's reader state does, and the index's ETag, so an unchanged feed costs one request. Bundles are written decrypted, exactly as stored, as `<out>/<stream>/<published_at with : as ->-<first 12 hex of the bundle's SHA-256>.zip` (so two different bundles never share a name), and a different file already there is never overwritten.

Exit status for `feed check` and `feed pull`:

- **0**: everything is accepted, unchanged or withdrawn, and the key set (if the publisher serves one) was accepted. A key set that couldn't be fetched (a failure other than 404) while a pin, an approved key or a held key set can still check signatures is printed on stderr as `keys: failed: …` and is not on its own a reason for another status.
- **1**: a stream was refused or failed, the index was refused, the key set was refused (`keys: <code>` on stdout), or a key waits for approval (`keys: needs_approval`).
- **2**: the feed couldn't be read; or its key set couldn't be fetched and nothing else (a pin, an approved key, a held key set) says whether the publisher signs, so a 403 on `keys.json` can't make a signing publisher look like one without keys; or the arguments or connection file are wrong.

#### Feeds in S3

A feed in an S3-compatible bucket is read with presigned GETs. The reader's access key needs `s3:ListBucket` on the feed's prefix as well as `s3:GetObject`: a reader asks for files that may not exist (`feed.json.age` beside `feed.json`, and `feed.sig`), and S3 answers `404` for a missing object only to a key that may list the bucket. To any other key it answers `403`, which the reader reports as an error.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
