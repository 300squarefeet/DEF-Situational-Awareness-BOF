# DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite

> All Rust ports + OPSEC hardening + persistence BOFs — **by Dani**.

A workspace of Cobalt Strike-compatible BOFs written in Rust, derived from the
TrustedSec, REDMED-X, and Outflank C BOF collections. Hardened with indirect
syscalls (HalosGate), djb2 API hashing, compile-time string encryption
(obfstr), and panic-abort `no_std` for safe execution inside Beacon.

Every BOF prints a MITRE ATT&CK banner before its main logic so operators
know exactly which technique they're firing.

## Phase status

- [x] Phase 1: Workspace + toolchain + canaries (uptime, hostname, whoami)
- [x] Phase 2: 25 Situational Awareness BOFs
- [x] Phase 3: 18 Remote Operations BOFs
- [x] Phase 4: 20 OperatorsKit + C2-Collection BOFs
- [x] Phase 5: 2 Persistence BOFs (schtask-com + lnk-startup)
- [x] Phase 6: InlineExecuteEx OPSEC fork (bofx loader)
- [ ] Phase 7+: Tier-3 RegisterTaskDefinition + AES blob loader + LDAP/SSPI helpers

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
