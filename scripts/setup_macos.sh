#!/usr/bin/env bash
# scripts/setup_macos.sh — one-time toolchain setup for macOS dev machine.
# Author: Dani <daniagungg@gmail.com>
set -euo pipefail

echo "==> Rust toolchain (pinned by rust-toolchain.toml)"
rustup show active-toolchain >/dev/null 2>&1 || rustup toolchain install nightly-2025-01-25
rustup component add rust-src clippy rustfmt --toolchain nightly-2025-01-25
rustup target add x86_64-pc-windows-gnu i686-pc-windows-gnu aarch64-apple-darwin \
    --toolchain nightly-2025-01-25

echo "==> MinGW-w64 (for std archive shims + boflink linkage)"
if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    if command -v brew >/dev/null 2>&1; then
        brew install mingw-w64
    else
        echo "Homebrew required to install mingw-w64 — install from https://brew.sh"
        exit 1
    fi
fi

echo "==> boflink (TrustedSec) + cargo-make"
rustup run nightly-2025-01-25 cargo install boflink || cargo install --git https://github.com/trustedsec/boflink boflink || true
cargo install --locked cargo-make || true

echo "==> Optional: llvm tools (for verify_coff.sh)"
if ! command -v llvm-objdump >/dev/null 2>&1; then
    brew install llvm || echo "WARN: llvm not installed — verify_coff.sh will be limited"
fi

echo "==> Verify"
rustup run nightly-2025-01-25 cargo --version
rustup target list --installed
which boflink && boflink --version
echo "==> Setup complete."
