#!/usr/bin/env bash
# scripts/build_one.sh — build a single BOF crate to dist/<bof>.{x64,x86}.o
# Usage: bash scripts/build_one.sh <crate-name>   (e.g. uptime)
# Author: Dani <daniagungg@gmail.com>
set -euo pipefail

# Ensure rustup proxy is first in PATH so `cargo +toolchain` directives work
export PATH="$HOME/.cargo/bin:$PATH"

CRATE="${1:?usage: build_one.sh <crate-name>}"
UNDER="${CRATE//-/_}"
mkdir -p dist

# Locate manifest
MANIFEST=$(cargo metadata --no-deps --format-version 1 \
    | jq -r --arg n "$CRATE" '.packages[] | select(.name == $n) | .manifest_path')

if [[ -z "$MANIFEST" ]]; then
    echo "ERROR: crate '$CRATE' not found in workspace" >&2
    exit 1
fi

CRATE_DIR=$(dirname "$MANIFEST")

for tgt in x86_64-pc-windows-gnu i686-pc-windows-gnu; do
    arch=$([[ "$tgt" == x86_64* ]] && echo x64 || echo x86)
    mingw=$([[ "$tgt" == x86_64* ]] && echo --mingw64 || echo --mingw32)
    echo "==> $CRATE [$arch]"
    cargo +nightly-2025-01-25 build --release --target "$tgt" --manifest-path "$MANIFEST"
    archive="target/$tgt/release/lib${UNDER}.a"
    out="dist/${CRATE}.${arch}.o"
    args=("$mingw" "$archive" -lkernel32 -ladvapi32 -lole32 -loleaut32 -o "$out")
    [[ "$arch" == "x86" ]] && args+=(--entry-symbol "_go")
    boflink "${args[@]}"
    ls -la "$out"
done
echo "==> done: dist/${CRATE}.{x64,x86}.o"
