<div align="center">

# DEF Situational Awareness BOF

**A Rust-native Beacon Object File suite for Cobalt Strike — situational awareness, remote ops, persistence, and OPSEC tooling.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20x86__64%20%2F%20x86-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

</div>

---

## Overview

A Cargo workspace of **156+ Cobalt Strike-compatible BOFs** written in Rust, derived
from the TrustedSec, REDMED-X, and Outflank collections, ported to a `no_std`
panic-abort runtime safe to execute inside a Beacon process.

Every BOF prints a **MITRE ATT&CK banner** before its main logic so operators
know exactly which technique they are firing, and every Win32 call is resolved
at runtime by **djb2 hash** with **compile-time string encryption (obfstr)** so
no telltale API names or strings remain in the resulting `.o` artefact.

> **Authorized use only.** This project is published for offensive-security
> research, red-team engagements, and defensive detection development. Do not
> deploy against systems you are not contractually authorized to assess.

## Features

- **156+ BOFs** spanning Situational Awareness, Remote Operations, OperatorsKit,
  C2-Collection, and Persistence categories
- **Rust-native** — `no_std`, panic-abort, `#![no_main]`, fits the Beacon
  execution model with zero runtime dependencies
- **OPSEC hardened** — indirect syscalls (HalosGate), djb2 API hashing,
  `obfstr` compile-time string encryption, generic error messages with no
  API leakage, bounds checking on all parser paths
- **MITRE ATT&CK aligned** — every BOF declares its techniques as a `const`
  and emits them at runtime; see [docs/mitre-mapping.md](docs/mitre-mapping.md)
- **Cobalt Strike aggressor** — `aggressor/dani-suite.cna` registers all
  BOFs as beacon commands
- **Cross-compiled on macOS / Linux / Windows** via the `cargo-make` task runner
- **InlineExecuteEx OPSEC fork** — bundled `bofx` loader in `tools/` for
  in-process execution outside Beacon

## Phase status

| Phase | Scope | BOFs |
|:--|:--|---:|
| 1 | Workspace, toolchain, canaries (`uptime`, `hostname`, `whoami`) | 3 |
| 2 | Situational Awareness | 62 |
| 3 | Remote Operations | 44 |
| 4 | OperatorsKit + C2-Collection | 48 |
| 5 | Persistence (`schtask-com`, `lnk-startup`) | 2 |
| 6 | InlineExecuteEx OPSEC fork (`bofx` loader) | ✓ |
| 7 | `RegisterTaskDefinition` COM-based scheduled task persistence | ✓ |
| 8 | AES-256-CBC in-memory blob decryption (`aes-loader`) | 1 |
| 9 | LDAP/SSPI Kerberos helpers + `asreproast` + `enum-delegation` | 3 |

## Quick start

### Prerequisites

- Rust stable (`rustup`) with the `x86_64-pc-windows-gnu` and
  `i686-pc-windows-gnu` targets
- `cargo-make` (`cargo install cargo-make`)
- `mingw-w64` (cross-link toolchain)
- macOS users: `bash scripts/setup_macos.sh` installs the above via Homebrew

### Build

```bash
# One-time setup (macOS)
bash scripts/setup_macos.sh

# Build every BOF (x64 + x86)
cargo make build-all

# Build a single BOF
bash scripts/build_one.sh situational-awareness/whoami
```

Artefacts land in `dist/`:

```
dist/
├── whoami.x64.o
├── whoami.x86.o
├── hostname.x64.o
├── hostname.x86.o
├── ...
└── manifest.json
```

`manifest.json` is a machine-readable index of every BOF, its techniques, and
its expected argument shape — useful for tooling that wants to wrap the
collection programmatically.

### Verify

```bash
bash scripts/verify_coff.sh        # validates each .o is a well-formed COFF
```

## Run inside Cobalt Strike

Load the aggressor script:

```
cs > Cobalt Strike → Script Manager → Load → aggressor/dani-suite.cna
```

Then call any BOF as a Beacon command:

```
beacon> whoami
================================================
  whoami — DEF SA BOF
================================================
  [MITRE] T1033 - System Owner/User Discovery (Discovery)
  [MITRE] T1134 - Access Token Manipulation (Privilege Escalation)
------------------------------------------------
USER:   CORP\jdoe
SID:    S-1-5-21-...
GROUPS: BUILTIN\Users, ...
TOKEN:  Primary, Impersonation Level: 0
```

Or invoke the raw `.o` directly:

```
beacon> inline-execute dist/whoami.x64.o
```

## Project layout

```
.
├── common/                # shared helpers (parser, formatter, MITRE banner)
├── bof-ldap/              # no_std wldap32 wrapper (connect, bind, search)
├── bof-sspi/              # no_std secur32 wrapper (Kerberos AP-REQ)
├── bof-kerberos/          # Kerberos enumeration helpers (LDAP filters, UAC)
├── situational-awareness/ # Phase 1–2 + Phase 9 BOFs
├── remote-ops/            # Phase 3 BOFs
├── operators-kit/         # Phase 4 BOFs (OperatorsKit port)
├── c2-collection/         # Phase 4 BOFs (C2-Collection port)
├── persistence/           # Phase 5 + 7 + 8 BOFs (schtask-com, lnk-startup, aes-loader)
├── tools/                 # bundled tooling (InlineExecuteEx OPSEC fork)
├── aggressor/             # Cobalt Strike .cna wrappers
├── scripts/               # build / verify / manifest helpers
├── docs/                  # MITRE mapping + per-BOF notes
└── dist/                  # compiled .o artefacts (gitignored)
```

## OPSEC posture

| Layer | Technique |
|:--|:--|
| Syscalls | HalosGate indirect syscall resolution (no static IAT entries) |
| API resolution | djb2-hashed `GetProcAddress` (no plaintext API names in `.rodata`) |
| Strings | `obfstr` compile-time XOR (no plaintext strings in `.o`) |
| Errors | Generic operator-facing messages — never leak API name on failure |
| Memory | Bounds-checked parsers; `no_std`/panic-abort prevents panic strings |
| Persistence | No on-disk artefacts; persistence BOFs use COM-only paths |

See [docs/mitre-mapping.md](docs/mitre-mapping.md) for full ATT&CK coverage.

## Roadmap

All core phases are complete. Potential future work:

- Additional persistence primitives (WMI event subscription, registry run keys via COM)
- Token manipulation BOFs (impersonation, S4U2Self)
- ETW/AMSI bypass improvements
- Linux cross-compilation target for testing harnesses

## Acknowledgements

This collection ports and refines work from the upstream C BOF projects:

- [trustedsec/CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)
- [trustedsec/CS-Remote-OPs-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF)
- [outflanknl/C2-Tool-Collection](https://github.com/outflanknl/C2-Tool-Collection)
- [Cobalt-Strike/OperatorsKit](https://github.com/Cobalt-Strike/OperatorsKit)
- [anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)

## Contributing

Pull requests welcome. See [CONTRIBUTORS.md](CONTRIBUTORS.md) for current
maintainers. Open an issue first to discuss scope before sending a large patch.

When adding a new BOF:

1. Create a crate under the appropriate phase directory
2. Wire it into the workspace `Cargo.toml`
3. Add its row to `docs/mitre-mapping.md`
4. Add its aggressor alias to `aggressor/dani-suite.cna`
5. Re-run `cargo make build-all && bash scripts/verify_coff.sh`

## License

[MIT](LICENSE) © Dani

## Disclaimer

Provided **as-is for authorized security research and red-team engagements**.
The maintainers accept no liability for misuse. Always operate within the scope
of a signed engagement letter and applicable law.
