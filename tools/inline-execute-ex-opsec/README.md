<!--
SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
SPDX-License-Identifier: MIT
-->

# bofx — OPSEC-hardened InlineExecuteEx fork

> Forked from [0xTriboulet/InlineExecuteEx](https://github.com/0xTriboulet/InlineExecuteEx) (MIT).
> COFFLoader core from [TrustedSec/COFFLoader](https://github.com/trustedsec/COFFLoader) (BSD).
> OPSEC modifications by **Dani &lt;daniagungg@gmail.com&gt;**.

`bofx` is a Cobalt Strike BOF that loads OTHER BOFs (or BOF-PEs) inline
inside a beacon. It is the operator-facing test harness for this
workspace's Rust BOFs — every `dist/*.x64.o` produced here can be
inline-executed via `bofx`.

## Modifications vs upstream (the 8-item OPSEC patch set)

| # | Upstream behaviour | OPSEC fork behaviour | Reason |
|---|--------------------|----------------------|--------|
| 1 | ASCII banner `"BOF+"` and `"[EXPERIMENTAL] I heard you like BOFs"` printed on `.cna` load; operator command `inline-execute-ex` | Banner removed; command renamed to `bofx` (configurable via `Makefile` `NAME=`) | YARA / aggressor-string signature reduction |
| 2 | Plaintext symbol names in COFF object (`runBof`, `runPE`, `isValidCoff`, `g_apiTable`, …) | `-fvisibility=hidden`, `-fvisibility-inlines-hidden`, `--strip-all`, internal `static` qualifiers | Loader-fingerprint reduction |
| 3 | DFR cache (`g_if` / `internal_func_ptr_table`) sits plaintext in `.bss` for beacon lifetime | Cache wiped at every `go` exit via `zero_dfr_table()` (volatile pointer wipe) | Memory-scanner resistance |
| 4 | COFF parser strings (`".text"`, `".data"`, `".rdata"`, `".pdata"`, `".bss"`, `"go"`, `"_go"`, `"MSVCRT"`, `"ntdll"`, `"kernel32"`) live in `.rdata` | Routed through `OBF("...")` (compile-time XOR with per-index key) | Static-signature reduction |
| 5 | ~30 verbose `BeaconPrintf(CALLBACK_ERROR, "human string")` call sites | Single `BofxErr` enum + `bofx_err()` emits only `"E:%02x"` — human mapping lives in `docs/error-codes.md`, never in the binary | Plaintext footprint reduction |
| 6 | BOF loaded from plaintext file path | Reserved for `bofx-enc` (AES-128-CBC blob variant) — **deferred to v0.2**; see "AES variant" below | EDR file-scan avoidance |
| 7 | `.cna` script has no preflight check on the input `.o` file | Optional SHA-256 preflight: `@BOFX_WHITELIST` in `bofx.cna` — operator populates per engagement | Anti-fat-finger / wrong-file load |
| 8 | Mapped sections + DFR cache leak into beacon address space across loads | `BofxScope` RAII wrapper: `BeaconVirtualFree` mapped image + zero DFR cache on every return path | Beacon memory hygiene |

What is *intentionally not* modified (binary compat):

- `API_TABLE` struct layout & version — must stay byte-for-byte compatible with upstream PIC BOFs.
- COFFLoader core parser logic in `coff.h`.
- BOF-PE loader core logic in `bofpe.h`.

## Layout

```
tools/inline-execute-ex-opsec/
├── README.md                  # this file
├── UPSTREAM.md                # how to drop upstream sources in + patch checklist
├── Makefile                   # MinGW cross-build from macOS
├── src/
│   ├── bof.cpp                # OPSEC entry + teardown wrapper (this fork)
│   ├── obfstr.h               # NEW: compile-time XOR string macros
│   └── (drop upstream here)   # bof.cpp core / coff.h / bofpe.h / beacon.h / api_table.h
├── aggressor/
│   └── bofx.cna               # banner stripped, command renamed, preflight hook
├── scripts/
│   └── encrypt_bof.py         # AES blob encryptor for Phase 7 (bofx-enc variant)
└── build/                     # output: bofx.x64.o / bofx.x86.o
```

## Build (macOS cross via MinGW)

Prerequisite: `brew install mingw-w64`.

```bash
cd tools/inline-execute-ex-opsec
make CROSS=x86_64-w64-mingw32- ARCH=x64    # -> build/bofx.x64.o
make CROSS=i686-w64-mingw32-   ARCH=x86    # -> build/bofx.x86.o
make clean
```

To rename the operator command at build time:

```bash
make CROSS=x86_64-w64-mingw32- ARCH=x64 NAME=lol   # -> build/lol.x64.o
```

## Usage in Cobalt Strike

```
[CS console]
beacon> [Aggressor → Load... → aggressor/bofx.cna]
beacon> bofx C:\path\to\your-bof.x64.o go "args"
```

With preflight whitelist (recommended for live engagements):

```sleep
# inside bofx.cna or a sibling .cna
@BOFX_WHITELIST = @(
    "3f8c0a...d4",   # sha256 of dist/whoami.x64.o
    "9e4a1b...c1",   # sha256 of dist/uptime.x64.o
);
```

`bofx` will refuse to load any file whose SHA-256 isn't in the list.

## AES-encrypted blob variant (`bofx-enc`) — deferred

The design spec calls for a second variant that loads an AES-128-CBC
encrypted blob and decrypts it in-memory before parsing (EDR file-scan
avoidance). This is **deferred to Phase 7+**. Track:
`scripts/encrypt_bof.py` is a stub.

## Upstream attribution

This component vendors OPSEC modifications atop:

| Project | Author | License |
|---|---|---|
| InlineExecuteEx | 0xTriboulet | MIT |
| COFFLoader (via InlineExecuteEx) | TrustedSec | BSD |

All OPSEC modifications and integration code by Dani &lt;daniagungg@gmail.com&gt;.
