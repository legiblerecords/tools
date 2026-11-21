#!/bin/sh
# Builds the WebAssembly module and its two JavaScript wrappers:
#   dist/node: CommonJS for Node, ready to use with no setup;
#   dist/web:  an ES module for browsers and bundlers, which needs `await init()`.
#
# Needs the wasm32-unknown-unknown Rust target and wasm-bindgen-cli at the
# same version as the wasm-bindgen crate in Cargo.lock.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cd "$root"

cargo build -p legible-records-wasm --target wasm32-unknown-unknown --release --locked
wasm=target/wasm32-unknown-unknown/release/legible_records_wasm.wasm

rm -rf "$here/dist"
wasm-bindgen "$wasm" --out-dir "$here/dist/node" --target nodejs
wasm-bindgen "$wasm" --out-dir "$here/dist/web" --target web
# The package is "type": "module", so the CommonJS wrapper needs a .cjs name.
mv "$here/dist/node/legible_records_wasm.js" "$here/dist/node/legible_records_wasm.cjs"
rm -f "$here/dist/node/.gitignore" "$here/dist/web/.gitignore"

if command -v wasm-opt >/dev/null 2>&1; then
  for dir in node web; do
    wasm-opt -Oz "$here/dist/$dir/legible_records_wasm_bg.wasm" -o "$here/dist/$dir/legible_records_wasm_bg.wasm"
  done
fi
cp "$root/LICENSE" "$here/LICENSE"
