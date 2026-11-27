#!/bin/sh
# Builds the WebAssembly module and its two JavaScript wrappers into dist/:
#   legible_records_wasm.cjs: CommonJS for Node, ready to use with no setup;
#   legible_records_wasm.js:  an ES module for browsers and bundlers, which
#                             needs `await init()`.
# Both load the one legible_records_wasm_bg.wasm next to them.
#
# Needs the wasm32-unknown-unknown Rust target and wasm-bindgen-cli at the
# same version as the wasm-bindgen crate in Cargo.lock. Runs wasm-opt when
# it's installed: binaryen version_123 (Ubuntu 24.04's 108 is too old).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cd "$root"

cargo build -p legible-records-wasm --target wasm32-unknown-unknown --profile wasm-release --locked
wasm=target/wasm32-unknown-unknown/wasm-release/legible_records_wasm.wasm

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
wasm-bindgen "$wasm" --out-dir "$work/node" --target nodejs
wasm-bindgen "$wasm" --out-dir "$work/web" --target web

# The two wrappers share one module, so it must be the same for both.
if ! cmp -s "$work/node/legible_records_wasm_bg.wasm" "$work/web/legible_records_wasm_bg.wasm"; then
  echo "the node and web builds produced different .wasm files; they can't share one" >&2
  exit 1
fi

rm -rf "$here/dist"
mkdir -p "$here/dist"
cp "$work/web/legible_records_wasm.js" "$work/web/legible_records_wasm.d.ts" "$here/dist/"
cp "$work/web/legible_records_wasm_bg.wasm" "$here/dist/"
# The package is "type": "module", so the CommonJS wrapper and its types get .cjs names.
cp "$work/node/legible_records_wasm.js" "$here/dist/legible_records_wasm.cjs"
cp "$work/node/legible_records_wasm.d.ts" "$here/dist/legible_records_wasm.d.cts"

if command -v wasm-opt >/dev/null 2>&1; then
  wasm-opt -Oz --strip-debug --strip-producers --strip-target-features \
    "$here/dist/legible_records_wasm_bg.wasm" -o "$here/dist/legible_records_wasm_bg.wasm"
fi

# An old wasm-opt can leave a module that won't load (binaryen 108 breaks
# wasm-bindgen's externref table), so check it loads before calling it built.
if command -v node >/dev/null 2>&1; then
  node -e 'require(process.argv[1])' "$here/dist/legible_records_wasm.cjs" ||
    { echo "the built module doesn't load; if wasm-opt ran, it may be too old (binaryen version_123 works)" >&2; exit 1; }
fi
cp "$root/LICENSE" "$here/LICENSE"
