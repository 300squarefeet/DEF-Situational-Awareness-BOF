// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
// Original C: TrustedSec/cs-situational-awareness-bof — tasklist.c
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::vec::Vec;

use rustbof::{println, eprintln};
use common::mitre::Technique;

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1057", name: "Process Discovery", tactic: "Discovery" },
];

// SystemProcessInformation = 5
const SYSTEM_PROCESS_INFORMATION: u32 = 5;
const STATUS_SUCCESS: i32 = 0;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    use common::syscalls::{SyscallEntry, resolve, do_syscall4};

    static ENTRY: SyscallEntry = SyscallEntry::new();
    const HASH: u32 = common::hash::djb2(b"NtQuerySystemInformation");

    let (ssn, addr) = unsafe { resolve(&ENTRY, HASH) }
        .map_err(|_| "resolve NtQuerySystemInformation failed")?;

    let mut size: u32 = 65536;
    let buf;
    loop {
        let mut v: Vec<u8> = alloc::vec![0u8; size as usize];
        let mut ret_len: u32 = 0;
        // NtQuerySystemInformation has 4 args:
        //   SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength*
        let status = unsafe {
            do_syscall4(
                SYSTEM_PROCESS_INFORMATION as usize,
                v.as_mut_ptr() as usize,
                size as usize,
                &mut ret_len as *mut u32 as usize,
                ssn,
                addr,
            )
        };
        if status == STATUS_SUCCESS {
            buf = v;
            break;
        } else if status == STATUS_INFO_LENGTH_MISMATCH {
            // Grow conservatively. Cap to avoid infinite loop on pathological cases.
            if size >= 64 * 1024 * 1024 {
                return Err("NtQuerySystemInformation buffer too large");
            }
            size = size.saturating_mul(2);
            continue;
        } else {
            return Err("NtQuerySystemInformation failed");
        }
    }

    // SYSTEM_PROCESS_INFORMATION layout (x64):
    //   +0    NextEntryOffset      ULONG
    //   +4    NumberOfThreads      ULONG
    //   +56   ImageName.Length     u16
    //   +58   ImageName.MaxLen     u16
    //   +64   ImageName.Buffer     *u16
    //   +80   UniqueProcessId      *void
    //   +156  SessionId            ULONG
    println!("{:<8} {:<8} {:<10} {}", "PID", "Threads", "Session", "Name");
    println!("{}", "--------------------------------------------");

    let mut offset: usize = 0;
    let mut iter_guard: usize = 0;
    loop {
        if offset >= buf.len() { break; }
        iter_guard += 1;
        if iter_guard > 65536 { break; } // hard sanity cap

        let ptr = unsafe { buf.as_ptr().add(offset) };
        let next_off = unsafe { core::ptr::read_unaligned(ptr as *const u32) } as usize;
        let num_threads = unsafe { core::ptr::read_unaligned(ptr.add(4) as *const u32) };
        let img_len = unsafe { core::ptr::read_unaligned(ptr.add(56) as *const u16) } as usize / 2;
        let img_buf = unsafe { core::ptr::read_unaligned(ptr.add(64) as *const *const u16) };
        let pid = unsafe { core::ptr::read_unaligned(ptr.add(80) as *const usize) };
        let session = unsafe { core::ptr::read_unaligned(ptr.add(156) as *const u32) };

        let name = wide_to_str(img_buf, img_len);
        println!("{:<8} {:<8} {:<10} {}", pid, num_threads, session, name);

        if next_off == 0 { break; }
        // Defensive: avoid backwards or zero-step which would loop forever
        if next_off < 64 { break; }
        offset = match offset.checked_add(next_off) {
            Some(v) if v <= buf.len() => v,
            _ => break,
        };
    }
    Ok(())
}

fn wide_to_str(ptr: *const u16, max_chars: usize) -> WStr {
    let mut s = WStr::new();
    if ptr.is_null() {
        for b in b"[System]" { s.push(*b); }
        return s;
    }
    for i in 0..max_chars.min(64) {
        let wc = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if wc == 0 { break; }
        s.push(if wc < 128 { wc as u8 } else { b'?' });
    }
    s
}

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
