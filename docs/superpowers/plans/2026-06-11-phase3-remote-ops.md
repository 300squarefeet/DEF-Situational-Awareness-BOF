# DEF-Situational-Awareness-BOF — Phase 3: Remote Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the **18 TrustedSec CS-Remote-Ops** BOFs to Rust, applying the same OPSEC primitives proven in Phase 1 + 2: HalosGate indirect syscalls, djb2 DFR, `obf!()` string encryption, panic-abort `no_std`, MITRE banner, RAII COM. Every BOF lives under `remote-ops/<crate>/`, follows the canary template (mitre + run + Result<(),&'static str>), and is added as a workspace member.

**Spec reference:** `docs/superpowers/specs/2026-06-11-dani-rustbof-opsec-suite-design.md` §6.2.

**Out of scope for Phase 3:** OperatorsKit (#47-58), C2-Tool-Collection (#59-66), persistence BOFs, InlineExecuteEx fork, and i686 support (deferred — syscall stubs are x86_64-only).

---

## Tiering — pick implementation order by complexity

| Tier | Count | Pattern | Crates |
|---|---|---|---|
| **A · DFR-only** | 5 | `dfr_fn!` macros + `obf_cstr!`/`obf!` for paths | `portscan`, `reg-save`, `sc-create`, `sc-delete`, `adduser` |
| **B · Indirect syscall** | 6 | `SyscallEntry` + `do_syscallN` | `enablepriv`, `suspendresume`, `etw-patch`, `amsi-patch`, `inject-ntcreate`, `inject-apc` |
| **C · COM / multi-API** | 4 | `ComGuard` + COM vtbl + DFR | `ghost-task`, `make-token`, `shspawnas`, `inject-crt` |
| **D · advanced** | 3 | mixed RWX flips, PEB write | `procdump`, `inject-ktable`, `global-unprotect` |

Implement in tier order (A → B → C → D). Each BOF follows the same 6-step task pattern below.

---

## Per-BOF task template (apply to every crate)

For each crate `<C>` listed in the implementation map below:

- [ ] **Step 1: Add workspace member** — append `"remote-ops/<C>"` to root `Cargo.toml` `[workspace] members`.
- [ ] **Step 2: Create `remote-ops/<C>/Cargo.toml`** mirroring the SA template:
  ```toml
  [package]
  name = "<C>"
  version.workspace = true
  edition.workspace = true
  authors.workspace = true
  license.workspace = true
  description = "<one-liner> — by Dani."

  [dependencies]
  rustbof.workspace = true
  common = { path = "../../common" }
  windows-sys = { workspace = true, features = [<minimal-feature-set>] }
  obfstr.workspace = true

  [lib]
  crate-type = ["staticlib"]
  name = "<C-with-underscores>"
  ```
- [ ] **Step 3: Create `remote-ops/<C>/src/lib.rs`** following the canary skeleton:
  ```rust
  // SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
  // SPDX-License-Identifier: MIT
  // Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
  // Credit: Rust port + OPSEC hardening — by Dani
  // Original C: TrustedSec/cs-remote-ops/<original-folder>
  //
  #![no_std]
  #![cfg_attr(not(test), no_main)]

  use rustbof::{println, eprintln};
  use common::{mitre::Technique, dfr_fn};
  // + obf, obf_cstr as needed

  const TECHNIQUES: &[Technique] = &[
      Technique { id: "<TXXXX>", name: "<name>", tactic: "<tactic>" },
  ];

  // dfr_fn!() blocks here

  #[rustbof::main]
  fn main(args: *mut u8, len: usize) {
      common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
      let mut parser = rustbof::data::DataParser::new(args, len);
      match run(&mut parser) {
          Ok(()) => {},
          Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
      }
  }

  fn run(_args: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
      // implementation
      Ok(())
  }
  ```
  Use `#[rustbof::main]` **with** `args/len` for any BOF that takes input (PID, target, exclude string, etc.). Use the no-arg form only for parameter-less BOFs.
- [ ] **Step 4: Apply OPSEC checklist (every BOF):**
  - [ ] No bare `extern crate alloc;` (the `#[rustbof::main]` macro injects it).
  - [ ] All Win32 calls go through `dfr_fn!` (no direct `extern "system" fn`).
  - [ ] All Nt*/Zw* calls go through `SyscallEntry::new()` + `resolve()` + `do_syscallN`.
  - [ ] Every runtime literal (registry path, filename, CLSID guid string, COM ProgID, WMI namespace) wrapped in `obf!(let x = "...";)` or `obf_cstr!(let x = c"...";)`.
  - [ ] No plaintext sensitive strings in `println!` — use `obf!(let label = "...";); println!("{}", label);`.
  - [ ] Every COM pointer wrapped in `ComRef<T>` (Phase 4 may add more helpers; reuse `common::com::ComRef`/`Bstr`/`ComGuard`).
  - [ ] Any RWX page made by the BOF must be flipped back to RX before exit.
  - [ ] Errors return `Result<(), &'static str>`; no `unwrap()`/`expect()`/`panic!()`.
- [ ] **Step 5: Cross-build & verify**
  - `bash scripts/build_one.sh <C>` produces `dist/<C>.x64.o`.
  - `bash scripts/verify_coff.sh` passes (no leaked sensitive strings).
  - `strings dist/<C>.x64.o | grep -iE "<sensitive-token>"` returns zero results.
- [ ] **Step 6: Commit**
  - `git add remote-ops/<C>/ Cargo.toml`
  - `git commit -m "feat(<C>): port — <one-liner> (Dani)"`

---

## Implementation map — 18 crates

### Tier A · DFR-only

#### 29. `portscan` — TCP connect-scan (T1046)

- **Args:** `--targets <CIDR-or-list> --ports <list> --timeout <ms>`
- **APIs (DFR):** `WSAStartup`, `WSASocketW`, `WSAConnect` (non-blocking via `ioctlsocket FIONBIO`), `select`, `closesocket`, `WSACleanup`.
- **Features:** `Win32_Networking_WinSock`.
- **OPSEC:** never log full target list; limit per-result line; randomize port iteration order via small LCG seeded from `KUSER_SHARED_DATA.TickCount`.

#### 35. `reg-save` — Remote registry hive dump (T1003.002, T1012)

- **Args:** `--key <HKEY\\path> --output <file>`
- **APIs (DFR):** `RegOpenKeyExA`, `RegSaveKeyExA` (with `REG_LATEST_FORMAT=2`), `RegCloseKey`.
- **Privilege:** requires `SeBackupPrivilege` (call `enablepriv` first).
- **OPSEC:** `obf_cstr!(let path = c"<HKLM\\SAM>")`. Never include `SAM`/`SECURITY` strings as plaintext.

#### 36. `sc-create` — Remote service create + start (T1543.003)

- **Args:** `--target <UNC> --name <svc> --binpath <path> --display <name>`
- **APIs (DFR):** `OpenSCManagerA`, `CreateServiceA` (`SERVICE_DEMAND_START`), `StartServiceA`, `CloseServiceHandle`.
- **OPSEC:** treat `binpath` as untrusted; do not log it on success.

#### 37. `sc-delete` — Remote service delete (T1489)

- **Args:** `--target <UNC> --name <svc>`
- **APIs (DFR):** `OpenSCManagerA`, `OpenServiceA`, `ControlService(SERVICE_CONTROL_STOP)`, `DeleteService`, `CloseServiceHandle`.

#### 38. `adduser` — Local user create + group add (T1136.001)

- **Args:** `--user <name> --pass <pw> [--admin]`
- **APIs (DFR):** `NetUserAdd` (`USER_INFO_1`), `NetLocalGroupAddMembers` (when `--admin`).
- **Features:** `Win32_NetworkManagement_NetManagement`.
- **OPSEC:** never echo password back; on success log only username.

### Tier B · Indirect syscall

#### 32. `enablepriv` — Enable token privilege (T1134.002)

- **Args:** `--name <PrivName>` (e.g. `SeDebugPrivilege`, `SeBackupPrivilege`)
- **Syscalls:** `NtOpenProcessTokenEx` (use existing `common::token::open_current_process_token`), `LookupPrivilegeValueW` (DFR — keep advapi32 indirect via DFR), `NtAdjustPrivilegesToken`.
- **OPSEC:** privilege names obfuscated; never plaintext-log them.

#### 41. `suspendresume` — Suspend or resume PID (T1055)

- **Args:** `--pid <u32> --action {suspend|resume}`
- **Syscalls:** `NtOpenProcess` (`PROCESS_SUSPEND_RESUME=0x0800`), `NtSuspendProcess` / `NtResumeProcess`, `NtClose`.
- **All 1-arg syscalls — use `do_syscall4`** with arg padding zeros.

#### 30. `etw-patch` — Patch `EtwEventWrite` to `xor eax, eax; ret` (T1562.006)

- **DFR:** locate `ntdll!EtwEventWrite` via `common::syscalls::find_module_pub` + `find_export_pub`.
- **Syscalls:** `NtProtectVirtualMemory` (RW), write 4 bytes `33 C0 C3 90` (xor eax,eax;ret;nop), `NtProtectVirtualMemory` (restore), `NtFlushInstructionCache`.
- **OPSEC:** restore protection even on partial failure (use a guard struct in `Drop`). Bytes constant — must obfuscate via XOR with stack value.

#### 31. `amsi-patch` — Patch `AmsiScanBuffer` to return `E_INVALIDARG` (T1562.001)

- **DFR:** locate `amsi.dll!AmsiScanBuffer` (load `amsi.dll` via `LoadLibraryA(obf_cstr!(c"amsi.dll"))`).
- **Stub bytes:** `mov eax, 0x80070057; ret` (`B8 57 00 07 80 C3`).
- **Same protect-write-restore-flush pattern as etw-patch.** Extract a shared helper `remote-ops/common-patch.rs` if both BOFs land — or copy-paste; the patch is small.

#### 44. `inject-ntcreate` — `NtCreateThreadEx` shellcode inject (T1055)

- **Args:** `--pid <u32> --shellcode <hex>`
- **Syscalls:** `NtOpenProcess` (`PROCESS_CREATE_THREAD|VM_OPERATION|VM_WRITE|VM_READ|QUERY_LIMITED`), `NtAllocateVirtualMemory` (RW), `NtWriteVirtualMemory`, `NtProtectVirtualMemory` (→RX), `NtCreateThreadEx` (use `do_syscall6` — 11-arg syscall actually requires custom 11-arg stub; for Phase 3 limit to 6-arg `NtCreateThreadEx` simplified API by passing zeros for the trailing args via stack).
  - **Note:** `NtCreateThreadEx` is a **10-arg** syscall. Phase 3 must extend `common::syscalls` with `do_syscall10` *or* use a stack-frame pre-built shim. Decide on first attempt; if `do_syscall10` is needed, add it next to `do_syscall6` and reuse for `inject-apc`/`inject-ktable`.
- **OPSEC:** zero shellcode buffer in remote process via `NtFreeVirtualMemory` on early return.

#### 45. `inject-apc` — APC inject via `NtQueueApcThread` (T1055.004)

- **Args:** `--pid <u32> --shellcode <hex>`
- **Syscalls:** identical alloc+write+protect to `inject-ntcreate`, then `NtQueueApcThread` (4-arg) on each alertable thread enumerated via `NtQuerySystemInformation(SystemProcessInformation)` (already proven in `tasklist`).
- **OPSEC:** target only threads in alertable wait state; skip kernel threads.

### Tier C · COM / multi-API

#### 34. `ghost-task` — Hidden scheduled task (T1053.005)

- **Args:** `--name <task> --cmd <path> [--remove]`
- **COM:** `ITaskService`/`ITaskFolder`/`ITaskDefinition`/`IRegisteredTask` — same vtbl chain as `schtasksquery` but with `TASK_CREATE_OR_UPDATE`. After register, modify SD via `IRegisteredTask::SetSecurityDescriptor` to remove `READ` from `Authenticated Users` so the task is hidden from `schtasks /query` for non-admins.
- **OPSEC:** all COM strings (`\Microsoft\Windows\BackgroundTasks` etc.) via `obf_cstr!`.

#### 39. `make-token` — Cert-based token via `LogonUserA` (T1134.003)

- **Args:** `--user <user> --pass <pw> --domain <dom>`
- **APIs (DFR):** `LogonUserA`/`LogonUserExA` (`LOGON32_LOGON_NEW_CREDENTIALS=9`), `ImpersonateLoggedOnUser`, `RevertToSelf` (caller drives revert).
- **OPSEC:** print only LUID after impersonation; never echo password.

#### 40. `shspawnas` — Spawn process as user (T1134.002)

- **Args:** `--user <user> --pass <pw> --domain <dom> --cmdline <line>`
- **APIs (DFR):** `CreateProcessWithLogonW` (`LOGON_WITH_PROFILE=1`).
- **OPSEC:** all wide strings built at runtime via `ascii_to_wide_buf` from `obf!`-decrypted ASCII source.

#### 43. `inject-crt` — Classic `CreateRemoteThread` inject (T1055.002)

- **Args:** `--pid <u32> --shellcode <hex>`
- **APIs (DFR):** `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread`, `CloseHandle`.
- **Why DFR-only here:** kept as the "loud baseline" so operators can A/B test against syscall variants.
- **Mark as detectable** in MITRE banner caveat.

### Tier D · Advanced

#### 33. `procdump` — MiniDump LSASS or PID (T1003.001)

- **Args:** `--pid <u32> --output <path>`
- **APIs (DFR):** `MiniDumpWriteDump` (load `dbghelp.dll` via DFR `LoadLibraryA`).
- **Syscalls:** `NtOpenProcess`, `NtCreateFile` (output path).
- **OPSEC:** temp filename built from `obf!()`-mangled token + LCG suffix; never log full path on success.

#### 46. `inject-ktable` — KernelCallbackTable hijack (T1055)

- **Args:** `--pid <u32> --shellcode <hex>`
- **Syscalls:** `NtOpenProcess`, `NtQueryInformationProcess(ProcessBasicInformation)` → PEB ptr, read `KernelCallbackTable` slot in PEB, `NtAllocateVirtualMemory` shellcode in target, `NtWriteVirtualMemory` patch one slot of KCT, force window event to trigger callback (DFR `PostMessageW` `WM_NULL` to a window owned by the target).
- **OPSEC:** restore original KCT slot after trigger; never log PEB address.

#### 42. `global-unprotect` — Chrome cookie / DPAPI decrypt (T1555.003)

- **Args:** `--input <Local-State-path> --output <file>`
- **APIs (DFR):** `CryptUnprotectData`, `CryptStringToBinaryA` (b64 decode).
- **OPSEC:** master key never logged; output only (cookie-name, decrypted-value-len) tuples by default unless `--reveal` flag set.

---

## Phase 3 acceptance summary

- All 18 `remote-ops/*` crates compile clean on `x86_64-pc-windows-gnu` for both `dev` and `release` profiles.
- `bash scripts/build_all.sh` produces 18 new `.o` files in `dist/`; `dist/manifest.json` updates with SHA-256 entries.
- `bash scripts/verify_coff.sh` passes — no leaked plaintext for any of: `NtOpen*`, `MiniDumpWriteDump`, `EtwEventWrite`, `AmsiScanBuffer`, `LogonUserA`, `CreateProcessWithLogon`, `KernelCallbackTable`, `SeDebugPrivilege`, `SOFTWARE\\...`, `SYSTEM\\CurrentControlSet`.
- A **minimum** smoke run on a target Win10/11 VM covers: `enablepriv SeDebugPrivilege`, `etw-patch`, `procdump --pid <PID>`, `portscan --targets 127.0.0.1 --ports 80,443,3389`. Each prints its MITRE banner, no Beacon crash.
- `cargo make clippy` clean on the workspace.
- Tag: `git tag -a v0.3.0-phase3 -m "Phase 3: 18 Remote-Ops BOFs — by Dani"`.

---

## Known follow-ups (deferred to later phases)

- **`do_syscall10`** for `NtCreateThreadEx`: extend `common::syscalls`. Pattern is identical to `do_syscall6` (more `mov` from stack, larger stack offsets).
- **`amsi-patch` Defender bypass robustness:** modern Defender hooks AMSI in many places; the patch is best-effort.
- **`inject-ktable` Win11 24H2** changed KCT layout; needs OS-version detection (`KUSER_SHARED_DATA.NtBuildNumber`).
- **Privilege escalation gates:** several BOFs require admin/SYSTEM. Document required privilege per-BOF in `docs/mitre-mapping.md` Phase 3 update.
- **Persistence helper** (`schtask-com`, `lnk-startup`) is **Phase 5**, not Phase 3, even though `ghost-task` uses overlapping COM machinery.

---

## Suggested execution order

1. `enablepriv` (unblocks `procdump` + `reg-save` + others requiring SeDebug/SeBackup).
2. Tier A in order: `reg-save`, `sc-create`, `sc-delete`, `adduser`, `portscan`.
3. Tier B in order: `suspendresume`, `etw-patch`, `amsi-patch`, `inject-ntcreate`, `inject-apc`.
4. Tier C: `make-token`, `shspawnas`, `ghost-task`, `inject-crt`.
5. Tier D: `procdump`, `global-unprotect`, `inject-ktable`.

Each tier should land green (workspace builds + verify_coff passes) before the next tier starts.

---

_Maintainer: Dani <daniagungg@gmail.com>_
