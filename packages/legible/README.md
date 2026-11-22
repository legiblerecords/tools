# @legiblerecords/legible

[Legible Records](https://github.com/legiblerecords/spec) in JavaScript: expand short-form schemas to JSON Schema and generate them back, lint published types, and check that a new version of a type is compatible with the last. It's the same Rust code as the `legible` command-line tool, compiled to WebAssembly.

Status: early, not yet published.

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

`options` is `{ base?, common?, location? }`. Giving `base` marks a published type, and points shared names such as `date` at `org.legiblerecords.common`.

## Validating records

This package doesn't validate records. Expanded schemas are standard JSON Schema 2020-12, so use a JavaScript validator such as [Ajv](https://ajv.js.org) (with `ajv/dist/2020` and `ajv-formats`), adding `org.legiblerecords.common` and your types to it. Or use `legible validate` from the command-line tool.

## License

Apache License 2.0.
