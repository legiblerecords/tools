# Legible Records tools

Tools for [Legible Records](https://github.com/legiblerecords/spec): legible, portable, pragmatic security records.

Status: early. Nothing here is released yet.

## What's planned

- **`legible`**, a command-line tool: expand short-form schemas to JSON Schema and generate them back, lint published types, check that a new version of a type is compatible with the last, and validate records.
- **A Rust crate** with the same functions, for tools that write or read Legible Records.
- **An npm package**, built from the same Rust code as WebAssembly, for browser tools, editors and agents.

All of them implement the [spec](https://github.com/legiblerecords/spec) and are tested against its vectors and fixtures.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
