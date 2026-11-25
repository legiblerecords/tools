---
name: legible-records
description: Use when turning exports (HR, identity provider, GitHub, MDM, scanners, policies, controls, risk decisions) into Legible Records, or packing, signing, verifying or encrypting them as bundles; when a file has "$type" and "version", a bundle has manifest.json or records/<kind>.ndjson, a type is named tech.monorail.* or org.legiblerecords.*; or when records are going to Monorail's Track.
---

# Legible Records

Legible Records are security records as plain JSON: each file names its `$type` and `version`. They travel in bundles: zips with a manifest of SHA-256 hashes, optionally signed and encrypted. **Write the records yourself; let the `legible` tool do everything with bytes, hashes, manifests and signatures.**

## Get the tool, docs and types first

| What | Where |
|---|---|
| The `legible` tool | `cargo install --git https://github.com/legiblerecords/tools legible` (Rust). Or `npx @legiblerecords/legible@0.1.0`, which has the schema, record and bundle commands, including `record hash`, and age encryption, but no feeds. |
| The docs, for models | `https://legiblerecords.org/llms.txt` lists every page as Markdown; `/llms-full.txt` is all of it in one file. |
| The spec | `https://legiblerecords.org/spec/records.md` and the other pages under Specification in `llms.txt`. The test vectors are in `https://github.com/legiblerecords/spec`, under `vectors/`. The spec is normative: where a guide differs, the spec is right. |
| Monorail's types | `https://github.com/Monorail-Tech/track-legible-records`, `schemas/<type>/v<n>.yaml`, and the docs' Monorail types page. |

If `legible` is already on your path or you were given a binary, use that: check it with `legible --version`. If you can't get the tool, stop and say what's missing. Don't write `manifest.json`, hashes, record sets or signatures by hand: the bytes must be canonical, and a bundle that is nearly right is refused.

## Using it or implementing it

This skill is for **using** Legible Records: writing records, packing and checking bundles, and running `legible`. To **implement** any part of it in your own code, such as a bundle reader, a signature or key-set check, a schema expander or a port of the tools, follow the spec, not this skill or the guides, and pass the spec's test vectors for that part. A summary leaves out exactly the cases an implementation gets wrong.

To read a feed, run `legible feed pull` (or `feed check`), or use the Rust library it is built on. Don't write a feed reader of your own: it decides what to trust, and the spec's [§ Reading a feed](https://legiblerecords.org/spec/feeds.md#reading-a-feed) and [§ Trust](https://legiblerecords.org/spec/feeds.md#trust) are long because an attacker who controls the storage or the publisher's server gets many chances.

## The workflow

```sh
B=https://monorail.tech/schemas/            # the base of the types' $ids
S="-s schemas/tech.monorail.people.person/v1.yaml -s schemas/tech.monorail.access.account/v1.yaml"   # every type you write

legible validate $S --base $B records/*/*.json     # exit 0: every record is valid
legible bundle pack $S --base $B records/ -o out.zip
legible bundle verify $S --base $B out.zip         # checks hashes, file list, references
legible bundle sign out.zip -k acme.key.json -o out.signed.zip   # only with the publisher's own key
```

- A short-form schema (`.yaml`) of a published type needs `--base`; without it the tool says `a published type needs the base option`. An expanded `.json` schema doesn't.
- `validate` and `verify` never fetch anything. Give every schema with `-s`.
- `pack` decides where each record goes in the bundle, from its type's title and its `id`, so lay out your input files however you like. It writes a kind with more than 1,000 records as one record set, `records/<kind>.ndjson`. Leave that to it.
- Signing needs the publisher's own key, which you normally won't have. Without one, the bundle goes unsigned: say so, and leave signing to whoever holds the key.
- To encrypt for email or another channel you don't trust, the npm command packs to `out.zip.age` with `--passphrase`, which prints a new passphrase. With the Rust tool, pipe through [age](https://age-encryption.org) to the reader's recipient: `legible bundle pack … -o - | age -r age1… > out.zip.age`. Send a passphrase by another channel, and never put one on a command line.

### Read what verify says

| It prints | It means |
|---|---|
| `signature: verified (<publisher> <key>)` | The signature was checked against a key you gave with `--pin` or `--key-set`. |
| `signature: unverified` | The bundle isn't signed. |
| `signature: unverified (signed by …; no trusted keys given)` | It is signed, but nothing was checked. |
| An outcome code, such as `bad_bundle` or `unknown_key`, and exit 1 | It fails. The code is defined in the docs' outcome codes page. |

Exit 0 means the bundle is well formed, not that a signature was checked. Report which line you got.

## Writing records

- **Fields:** use only the fields the type defines, plus `source_fields` for the source's own fields that nothing else covers. Never invent a value a source doesn't give: leave out an optional field such as `kind`, `as_of` or a date rather than guess one. When a **required** field isn't in the source, set it only from what the export itself implies, such as `status: active` for a list of current members, and say in your report that you did.
- **Ids:** `id` is a slug, and the same record keeps it in every export. Use the type's convention where its description gives one, such as `github-<numeric id>` for an account. Otherwise follow the type's example, such as `ana-lima` for a person.
- **Pointing at a person:** use `person: "person:<id>"` only when that person's record is in the same bundle **and** the source links them, such as an IdP field naming the account. Otherwise use `person_match`, with the identifiers and emails the source gives. `name` is for people to read; readers never match on it. When a link isn't stated, leave it unresolved and say so. A name that looks alike is not a link.
- **Identifiers:** `{ "system": "...", "id": "..." }`, with a lowercase system. The system's own name means its stable id. `github` is the numeric user id or `owner/repo`, and `github-login` is the login. `okta`, `entra` and `google` are the directory's user id, not the sign-in name. `serial` is a device serial as printed.
- **Records elsewhere:** point at a record in another bundle or from another publisher with an `externalRef`: `{type, key, publisher, revision, sha256}`. `type` is the full `$type`. `sha256` is what `legible record hash <file>` prints.
- **Provenance:** `produced_by` is the program that wrote the file, which can be your own script: `{app, build?}`. `source` is what it was built from: `{system, refs?, as_of?}`. Set `as_of` only from a date the export states.
- **Examples:** fixtures and examples are invented: `acme.example`, `Example Co`. Never put real client data in them.

### Shared shapes

These come from `org.legiblerecords.common`, which `legible` has built in. A type's short form names them without a prefix.

| Name | Shape |
|---|---|
| `identifier` | `{ "system": "github", "id": "4183920" }` |
| `personMatch` | `{ "emails": [...], "identifiers": [identifier, ...], "name": "..." }`: needs `emails` or `identifiers`, or both |
| `externalRef` | `{ "type": "<$type>", "key": "<id>", "publisher": "<domain>", "revision": 3, "sha256": "<content hash>" }`: needs `type` and `key` |
| `produced_by` | `{ "app": "...", "build": "...", "output": "..." }`: needs `app` |
| `source` | `{ "system": "...", "refs": [...], "as_of": "<date-time>" }`: needs `system` |
| `ref(kind)` | A string `"<kind>:<id>"`, such as `"person:ana-lima"`, resolving to a record in the same bundle |

## Before you hand it over, report

- What the bundle holds: a count per type.
- Every record you left unresolved, and why.
- The `verify` line, word for word, and whether it's signed or encrypted.
- Anything the data shows that the reader should act on, such as a suspended person whose account is still active.
