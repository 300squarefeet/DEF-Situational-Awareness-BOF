// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
// Original C: Outflank/C2-Tool-Collection — Psx/
//
//! `psx` — combined situational-awareness snapshot:
//!   1. Process list with parent PID + session + thread count
//!      (NtQuerySystemInformation/SystemProcessInformation — indirect syscall)
//!   2. Token integrity level for each process that can be opened
//!      (NtOpenProcessToken + NtQueryInformationToken/TokenIntegrityLevel — indirect)
//!   3. AV/EDR security-product presence via SCM service probe
//!      (DFR advapi32!OpenSCManagerW + OpenServiceW — same logic as enum-sec-products)
//!
//! This gives the operator a single panoramic view:
//!   PID   PPID  Sess Thd  Integrity  Name
//!   4     0     0    1    -          [System]
//!   ...
//! followed by the security product summary.
//!
//! No child processes are spawned. No WMI query. No tasklist.exe. All data
//! comes from native NT interfaces.

#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::vec::Vec;

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1057",     name: "Process Discovery",          tactic: "Discovery" },
    Technique { id: "T1134",     name: "Access Token Manipulation",  tactic: "Privilege Escalation" },
    Technique { id: "T1518.001", name: "Security Software Discovery",tactic: "Discovery" },
];

// ─── NT constants ─────────────────────────────────────────────────────────────
const SYSTEM_PROCESS_INFORMATION:      u32 = 5;
const STATUS_SUCCESS:                  i32 = 0;
const STATUS_INFO_LENGTH_MISMATCH:     i32 = 0xC0000004u32 as i32;

// Precomputed API hashes — byte literals are compile-time-const, no string in binary
const HASH_NT_OPEN_PROCESS:            u32 = common::hash::djb2(b"NtOpenProcess");
const HASH_NT_OPEN_PROCESS_TOKEN:      u32 = common::hash::djb2(b"NtOpenProcessToken");
const HASH_NT_QUERY_INFORMATION_TOKEN: u32 = common::hash::djb2(b"NtQueryInformationToken");
const HASH_NT_CLOSE:                   u32 = common::hash::djb2(b"NtClose");
const HASH_NT_QUERY_SYSTEM_INFO:       u32 = common::hash::djb2(b"NtQuerySystemInformation");

const TOKEN_QUERY:                     u32 = 0x0008;
const TOKEN_INTEGRITY_LEVEL_CLASS:     u32 = 25; // TokenIntegrityLevel
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

// Mandatory label RIDs → integrity string
const SECURITY_MANDATORY_UNTRUSTED_RID:  u32 = 0x0000;
const SECURITY_MANDATORY_LOW_RID:        u32 = 0x1000;
const SECURITY_MANDATORY_MEDIUM_RID:     u32 = 0x2000;
const SECURITY_MANDATORY_HIGH_RID:       u32 = 0x3000;
const SECURITY_MANDATORY_SYSTEM_RID:     u32 = 0x4000;

// ─── SCM constants ─────────────────────────────────────────────────────────────
const SC_MANAGER_CONNECT:   u32 = 0x0001;
const SC_MANAGER_ENUMERATE: u32 = 0x0004;
const SERVICE_QUERY_STATUS: u32 = 0x0004;

// ─── DFR declarations ─────────────────────────────────────────────────────────

dfr_fn!(
    open_sc_manager_w(machine: *const u16, db: *const u16, access: u32) -> usize,
    module = "advapi32.dll",
    api    = "OpenSCManagerW"
);

dfr_fn!(
    open_service_w(scm: usize, name: *const u16, access: u32) -> usize,
    module = "advapi32.dll",
    api    = "OpenServiceW"
);

dfr_fn!(
    query_service_status(svc: usize, status: *mut ServiceStatus) -> i32,
    module = "advapi32.dll",
    api    = "QueryServiceStatus"
);

dfr_fn!(
    close_service_handle(h: usize) -> i32,
    module = "advapi32.dll",
    api    = "CloseServiceHandle"
);

// ─── Struct helpers ───────────────────────────────────────────────────────────

#[repr(C)]
struct ServiceStatus {
    service_type:             u32,
    current_state:            u32,
    controls_accepted:        u32,
    win32_exit_code:          u32,
    service_specific_exit:    u32,
    check_point:              u32,
    wait_hint:                u32,
}

impl ServiceStatus {
    fn new() -> Self {
        Self {
            service_type: 0, current_state: 0, controls_accepted: 0,
            win32_exit_code: 0, service_specific_exit: 0,
            check_point: 0, wait_hint: 0,
        }
    }
}

fn svc_state(s: u32) -> &'static str {
    match s { 4 => "RUNNING", 1 => "STOPPED", _ => "OTHER" }
}

fn to_wide_64(s: &[u8]) -> ([u16; 64], usize) {
    let mut buf = [0u16; 64];
    let n = s.len().min(63);
    for (i, &b) in s[..n].iter().enumerate() { buf[i] = b as u16; }
    buf[n] = 0;
    (buf, n + 1)
}

// ─── Process + token logic ────────────────────────────────────────────────────

fn integrity_str(rid: u32) -> &'static str {
    match rid {
        SECURITY_MANDATORY_UNTRUSTED_RID => "Untrusted",
        SECURITY_MANDATORY_LOW_RID       => "Low",
        SECURITY_MANDATORY_MEDIUM_RID    => "Medium",
        SECURITY_MANDATORY_HIGH_RID      => "High",
        SECURITY_MANDATORY_SYSTEM_RID    => "System",
        _                                => "?",
    }
}

/// Read the mandatory integrity level RID from a process token.
/// Returns None if the process cannot be opened or the token query fails.
fn query_integrity(pid: usize) -> Option<u32> {
    use common::syscalls::{SyscallEntry, resolve, do_syscall4, do_syscall5};

    // NtOpenProcess
    static OP: SyscallEntry = SyscallEntry::new();
    let (op_s, op_a) = unsafe { resolve(&OP, HASH_NT_OPEN_PROCESS).ok()? };

    #[repr(C)]
    struct OA { len: u32, _r: [usize; 5] }
    #[repr(C)]
    struct CID { proc: usize, thd: usize }

    let oa  = OA { len: 48, _r: [0; 5] };
    let cid = CID { proc: pid, thd: 0 };
    let mut h_proc: usize = 0;
    let s0 = unsafe {
        do_syscall4(
            &mut h_proc as *mut usize as usize,
            PROCESS_QUERY_LIMITED_INFORMATION as usize,
            &oa as *const _ as usize,
            &cid as *const _ as usize,
            op_s, op_a,
        )
    };
    if s0 != STATUS_SUCCESS || h_proc == 0 { return None; }

    // NtOpenProcessToken
    static OT: SyscallEntry = SyscallEntry::new();
    let (ot_s, ot_a) = unsafe { resolve(&OT, HASH_NT_OPEN_PROCESS_TOKEN).ok()? };
    let mut h_tok: usize = 0;
    let s1 = unsafe {
        do_syscall4(
            h_proc,
            TOKEN_QUERY as usize,
            &mut h_tok as *mut usize as usize,
            0,
            ot_s, ot_a,
        )
    };
    nt_close(h_proc);
    if s1 != STATUS_SUCCESS || h_tok == 0 { return None; }

    // NtQueryInformationToken(TokenIntegrityLevel)
    // Returns TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES { Sid, Attributes } }
    // The last sub-authority of the SID is the mandatory integrity RID.
    static QT: SyscallEntry = SyscallEntry::new();
    let (qt_s, qt_a) = unsafe { resolve(&QT, HASH_NT_QUERY_INFORMATION_TOKEN).ok()? };
    let mut buf = [0u8; 64];
    let mut ret: u32 = 0;
    // NtQueryInformationToken(5-arg): TokenHandle, InfoClass, Buffer, BufLen, RetLen
    let s2 = unsafe {
        do_syscall5(
            h_tok,
            TOKEN_INTEGRITY_LEVEL_CLASS as usize,
            buf.as_mut_ptr() as usize,
            buf.len(),
            &mut ret as *mut u32 as usize,
            qt_s, qt_a,
        )
    };
    nt_close(h_tok);
    if s2 != STATUS_SUCCESS { return None; }

    // TOKEN_MANDATORY_LABEL: ptr to SID (8 bytes), then attributes (4 bytes).
    // The SID pointer is at offset 0. The SID itself:
    //   Revision(1) SubAuthorityCount(1) IdentifierAuthority[6] SubAuthority[n*4]
    // RID = last SubAuthority = SubAuthority[SubAuthorityCount-1]
    let sid_ptr = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const *const u8) };
    if sid_ptr.is_null() { return None; }
    let sub_count = unsafe { *sid_ptr.add(1) } as usize;
    if sub_count == 0 { return None; }
    // SubAuthority array starts at offset 8 (after Revision+SubAuthCount+IdentifierAuthority)
    let rid = unsafe {
        core::ptr::read_unaligned(sid_ptr.add(8 + (sub_count - 1) * 4) as *const u32)
    };
    Some(rid)
}

fn nt_close(h: usize) {
    use common::syscalls::{SyscallEntry, resolve, do_syscall4};
    static E: SyscallEntry = SyscallEntry::new();
    if let Ok((s, a)) = unsafe { resolve(&E, HASH_NT_CLOSE) } {
        let _ = unsafe { do_syscall4(h, 0, 0, 0, s, a) };
    }
}

// ─── Wide-to-narrow helper ───────────────────────────────────────────────────

fn wide_to_str(ptr: *const u16, max: usize) -> WStr {
    let mut s = WStr::new();
    if ptr.is_null() {
        for b in b"[System]" { s.push(*b); }
        return s;
    }
    for i in 0..max.min(64) {
        let wc = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if wc == 0 { break; }
        s.push(if wc < 128 { wc as u8 } else { b'?' });
    }
    s
}

// ─── Entry ────────────────────────────────────────────────────────────────────

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(())  => {},
        Err(e)  => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // ── Section 1: Process snapshot ──────────────────────────────────────────
    use common::syscalls::{SyscallEntry, resolve, do_syscall4};

    static ENTRY: SyscallEntry = SyscallEntry::new();
    let (ssn, addr) = unsafe { resolve(&ENTRY, HASH_NT_QUERY_SYSTEM_INFO) }
        .map_err(|_| "resolve failed")?;

    let mut size: u32 = 65536;
    let buf;
    loop {
        let mut v: Vec<u8> = alloc::vec![0u8; size as usize];
        let mut ret_len: u32 = 0;
        let status = unsafe {
            do_syscall4(
                SYSTEM_PROCESS_INFORMATION as usize,
                v.as_mut_ptr() as usize,
                size as usize,
                &mut ret_len as *mut u32 as usize,
                ssn, addr,
            )
        };
        if status == STATUS_SUCCESS {
            buf = v;
            break;
        } else if status == STATUS_INFO_LENGTH_MISMATCH {
            if size >= 64 * 1024 * 1024 {
                return Err("buf too large");
            }
            size = size.saturating_mul(2);
            continue;
        } else {
            return Err("query failed");
        }
    }

    // SYSTEM_PROCESS_INFORMATION (x64) offsets:
    //   +0    NextEntryOffset  ULONG
    //   +4    NumberOfThreads  ULONG
    //   +56   ImageName.Length u16
    //   +64   ImageName.Buffer *u16
    //   +80   UniqueProcessId  *void  (usize)
    //   +88   ParentPID        *void  (usize)
    //   +156  SessionId        ULONG
    println!("{:<8} {:<8} {:<5} {:<5} {:<12} {}", "PID", "PPID", "Sess", "Thd", "Integrity", "Name");
    println!("{}", "--------------------------------------------------------------------");

    let mut offset:     usize = 0;
    let mut iter_guard: usize = 0;
    loop {
        if offset >= buf.len() { break; }
        iter_guard += 1;
        if iter_guard > 65536 { break; }

        let ptr = unsafe { buf.as_ptr().add(offset) };
        let next_off    = unsafe { core::ptr::read_unaligned(ptr                  as *const u32) } as usize;
        let num_threads = unsafe { core::ptr::read_unaligned(ptr.add(4)           as *const u32) };
        let img_len     = unsafe { core::ptr::read_unaligned(ptr.add(56)          as *const u16) } as usize / 2;
        let img_buf     = unsafe { core::ptr::read_unaligned(ptr.add(64)          as *const *const u16) };
        let pid         = unsafe { core::ptr::read_unaligned(ptr.add(80)          as *const usize) };
        let ppid        = unsafe { core::ptr::read_unaligned(ptr.add(88)          as *const usize) };
        let session     = unsafe { core::ptr::read_unaligned(ptr.add(156)         as *const u32) };

        let name = wide_to_str(img_buf, img_len);

        // Try to get integrity level (best-effort; skip System (PID 4) which
        // would require SeDebugPrivilege for NtOpenProcess to succeed).
        let integrity = if pid > 4 {
            match query_integrity(pid) {
                Some(rid) => integrity_str(rid),
                None      => "-",
            }
        } else {
            "System"
        };

        println!("{:<8} {:<8} {:<5} {:<5} {:<12} {}", pid, ppid, session, num_threads, integrity, name);

        if next_off == 0 { break; }
        if next_off < 64 { break; } // defensive
        offset = match offset.checked_add(next_off) {
            Some(v) if v <= buf.len() => v,
            _ => break,
        };
    }

    // ── Section 2: Security-product probe ────────────────────────────────────
    println!("");
    println!("{}", "════════════════ Security Products ════════════════");
    println!("{:<30} {}", "Service", "State");
    println!("{}", "--------------------------------------------");

    let scm = unsafe {
        open_sc_manager_w(
            core::ptr::null(),
            core::ptr::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE,
        )
    }.map_err(|_| "scm open failed")?;

    if scm == 0 {
        println!("[-] SCM open failed (no sec-product info)");
        return Ok(());
    }

    // Probe well-known AV/EDR services — names decrypted on-stack via obf!()
    obf! { let s01 = "WinDefend";       }  // Defender antivirus
    obf! { let s02 = "Sense";           }  // Defender ATP / MDE sensor
    obf! { let s03 = "WdNisSvc";        }  // Defender NIS
    obf! { let s04 = "MsMpSvc";         }  // Defender Malware Protection
    obf! { let s05 = "ekrn";            }  // ESET kernel
    obf! { let s06 = "EhttpSrv";        }  // ESET web access
    obf! { let s07 = "avast! Antivirus";}  // Avast
    obf! { let s08 = "avp";             }  // Kaspersky
    obf! { let s09 = "klif";            }  // Kaspersky filter
    obf! { let s10 = "MBAMService";     }  // Malwarebytes
    obf! { let s11 = "BdServiceHost";   }  // Bitdefender
    obf! { let s12 = "csagent";         }  // CrowdStrike Falcon
    obf! { let s13 = "SentinelAgent";   }  // SentinelOne
    obf! { let s14 = "Cylance";         }  // Cylance
    obf! { let s15 = "CarbonBlack";     }  // Carbon Black
    obf! { let s16 = "SAVService";      }  // Sophos AV
    obf! { let s17 = "TmPfw";           }  // Trend Micro

    let services: &[(&str, &str)] = &[
        (s01, s01), (s02, s02), (s03, s03), (s04, s04),
        (s05, s05), (s06, s06), (s07, s07), (s08, s08),
        (s09, s09), (s10, s10), (s11, s11), (s12, s12),
        (s13, s13), (s14, s14), (s15, s15), (s16, s16),
        (s17, s17),
    ];

    let mut found_any = false;
    for (name_bytes_src, label) in services {
        let (wide, _) = to_wide_64(name_bytes_src.as_bytes());
        let h = match unsafe { open_service_w(scm, wide.as_ptr(), SERVICE_QUERY_STATUS) } {
            Ok(h) if h != 0 => h,
            _ => continue,
        };
        let mut status = ServiceStatus::new();
        let ok = unsafe { query_service_status(h, &mut status as *mut ServiceStatus) }
            .unwrap_or(0);
        let _ = unsafe { close_service_handle(h) };
        if ok != 0 {
            println!("[+] {:<30} {}", label, svc_state(status.current_state));
            found_any = true;
        }
    }

    let _ = unsafe { close_service_handle(scm) };

    if !found_any {
        println!("[-] No known security products detected via SCM");
    }

    Ok(())
}

// ─── Stack-allocated display strings ─────────────────────────────────────────

struct WStr { buf: [u8; 64], len: usize }
impl WStr {
    fn new() -> Self { Self { buf: [0u8; 64], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for WStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
