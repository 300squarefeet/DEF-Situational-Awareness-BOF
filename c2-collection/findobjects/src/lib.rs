// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
// Original C: Outflank/C2-Tool-Collection — FindObjects/
//
//! `findobjects` — injection-candidate process finder.
//!
//! Calls NtQuerySystemInformation(SystemProcessInformation=5) to enumerate
//! all running processes and classifies each as [SAFE] or [PROTECTED] based
//! on image name. Protected processes include system-critical and EDR/AV hosts
//! that should not be targeted for injection.
//!
//! SYSTEM_PROCESS_INFORMATION (x64) offsets:
//!   +0    NextEntryOffset  ULONG   (0 = last entry)
//!   +4    NumberOfThreads  ULONG
//!   +56   ImageName.Length u16     (byte count of wide string)
//!   +64   ImageName.Buffer *u16
//!   +68   UniqueProcessId  HANDLE  (usize on x64)  ← NOTE: offset 68, not 80
//!   +76   InheritedFromUniqueProcessId HANDLE
//!   +160  SessionId        ULONG
//!
//! Wait — let's use the psx-verified offsets that are known to work:
//!   +56   ImageName.Length u16
//!   +64   ImageName.Buffer *u16
//!   +80   UniqueProcessId  (usize)
//!   +88   ParentPID        (usize)
//!   +156  SessionId        (u32)
//! (These match psx.lib.rs which is production-tested)
//!
//! MITRE: T1057 (Process Discovery)

#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::vec::Vec;
use rustbof::{println, eprintln};
use common::{mitre::Technique, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1057", name: "Process Discovery", tactic: "Discovery" },
];

const SYSTEM_PROCESS_INFORMATION: usize = 5;
const STATUS_SUCCESS:             i32   = 0;
const STATUS_INFO_LENGTH_MISMATCH: i32  = 0xC0000004u32 as i32;

// Precomputed hash — byte literal stays compile-time only
const HASH_NT_QUERY_SYSTEM_INFO: u32 = common::hash::djb2(b"NtQuerySystemInformation");

// SYSTEM_PROCESS_INFORMATION x64 offsets (same as psx, production-verified)
const OFF_NEXT_ENTRY:   usize = 0;
const OFF_NUM_THREADS:  usize = 4;
const OFF_IMG_LEN:      usize = 56;  // UNICODE_STRING.Length (u16, byte count)
const OFF_IMG_BUF:      usize = 64;  // UNICODE_STRING.Buffer (*u16)
const OFF_PID:          usize = 80;  // UniqueProcessId (usize)
const OFF_PPID:         usize = 88;  // InheritedFromUniqueProcessId (usize)
const OFF_SESSION:      usize = 156; // SessionId (u32)

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(())  => {},
        Err(e)  => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
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
                SYSTEM_PROCESS_INFORMATION,
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

    // Build protected process name list (obfuscated at compile time)
    obf! { let p01 = "csrss.exe";       }
    obf! { let p02 = "wininit.exe";     }
    obf! { let p03 = "smss.exe";        }
    obf! { let p04 = "winlogon.exe";    }
    obf! { let p05 = "MsMpEng.exe";     }
    obf! { let p06 = "MsSense.exe";     }
    obf! { let p07 = "SenseIR.exe";     }
    obf! { let p08 = "MsMpEngCP.exe";   }
    obf! { let p09 = "NisSrv.exe";      }
    obf! { let p10 = "lsass.exe";       }
    obf! { let p11 = "lsaiso.exe";      }
    obf! { let p12 = "MemCompression";  }
    obf! { let p13 = "Registry";        }
    obf! { let p14 = "System";          }
    obf! { let p15 = "Idle";            }

    let protected: &[&str] = &[
        p01, p02, p03, p04, p05, p06, p07, p08,
        p09, p10, p11, p12, p13, p14, p15,
    ];

    println!("{:<8} {:<8} {:<5} {:<5} {:<12} {}", "PID", "PPID", "Sess", "Thd", "Status", "Name");
    println!("{}", "--------------------------------------------------------------------");

    let mut offset:     usize = 0;
    let mut iter_guard: usize = 0;
    let mut safe_count:      usize = 0;
    let mut protected_count: usize = 0;

    loop {
        if offset >= buf.len() { break; }
        iter_guard += 1;
        if iter_guard > 65536 { break; }

        let ptr = unsafe { buf.as_ptr().add(offset) };
        let next_off    = unsafe { core::ptr::read_unaligned(ptr.add(OFF_NEXT_ENTRY)  as *const u32) } as usize;
        let num_threads = unsafe { core::ptr::read_unaligned(ptr.add(OFF_NUM_THREADS) as *const u32) };
        let img_len     = unsafe { core::ptr::read_unaligned(ptr.add(OFF_IMG_LEN)     as *const u16) } as usize / 2;
        let img_buf     = unsafe { core::ptr::read_unaligned(ptr.add(OFF_IMG_BUF)     as *const *const u16) };
        let pid         = unsafe { core::ptr::read_unaligned(ptr.add(OFF_PID)         as *const usize) };
        let ppid        = unsafe { core::ptr::read_unaligned(ptr.add(OFF_PPID)        as *const usize) };
        let session     = unsafe { core::ptr::read_unaligned(ptr.add(OFF_SESSION)     as *const u32) };

        let name = wide_to_wstr(img_buf, img_len);
        let name_str = name.as_str();

        // Classify
        let is_protected = protected.iter().any(|&p| icase_eq(name_str.as_bytes(), p.as_bytes()));
        let status_tag = if is_protected { "[PROTECTED]" } else { "[SAFE]" };
        if is_protected { protected_count += 1; } else { safe_count += 1; }

        println!("{:<8} {:<8} {:<5} {:<5} {:<12} {}", pid, ppid, session, num_threads, status_tag, name_str);

        if next_off == 0 { break; }
        if next_off < 64 { break; } // defensive minimum entry size
        offset = match offset.checked_add(next_off) {
            Some(v) if v <= buf.len() => v,
            _ => break,
        };
    }

    println!("");
    println!("[*] {} safe injection candidates, {} protected processes skipped",
        safe_count, protected_count);

    Ok(())
}

// ─── Stack-allocated wide-to-ASCII string ────────────────────────────────────

struct WStr { buf: [u8; 64], len: usize }
impl WStr {
    fn new() -> Self { Self { buf: [0u8; 64], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?")
    }
}

fn wide_to_wstr(ptr: *const u16, max: usize) -> WStr {
    let mut s = WStr::new();
    if ptr.is_null() {
        for b in b"[System]" { s.push(*b); }
        return s;
    }
    for i in 0..max.min(63) {
        let wc = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if wc == 0 { break; }
        s.push(if wc < 128 { wc as u8 } else { b'?' });
    }
    s
}

/// Case-insensitive ASCII byte-slice comparison.
fn icase_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b.iter()).all(|(&x, &y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}
