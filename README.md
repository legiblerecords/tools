# Legible Records tools

Tools for [Legible Records](https://github.com/legiblerecords/spec): legible, portable, pragmatic security records.

Status: early. Nothing here is released yet.

## What's here

| Path | What it is |
|---|---|
| [crates/legible](crates/legible) | `legible`, the command-line tool |
| [crates/legible-records](crates/legible-records) | The Rust library the tool is built on |

An npm package, built from the same Rust code as WebAssembly, is planned.

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

For a published type, give the base of its `$id` with `--base`, such as `--base https://monorail.tech/schemas/`. Shared names such as `date` then point at `org.legiblerecords.common`.

```sh
legible expand appetite.yaml --base https://monorail.tech/schemas/ > appetite.json
legible lint appetite.json --base https://monorail.tech/schemas/
legible validate -s appetite.json decision.json
```

Exit status is 0 when everything passes, 1 when the input has problems, and 2 when the tool couldn't run. `validate` never fetches anything: every schema it needs is given with `-s`, and `org.legiblerecords.common` version 1 is built in.

Both implement the [spec](https://github.com/legiblerecords/spec), and are tested against its vectors: `crates/legible-records/tests/vectors/` holds a copy, and `SOURCE` says which spec commit it came from.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
