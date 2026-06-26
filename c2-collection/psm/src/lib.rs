// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
// Original C: Outflank/C2-Tool-Collection — Psm/
//
//! `psm` — enumerate modules loaded into the current process via PEB walk.
//!
//! Reads the PEB at gs:[0x60], follows Ldr.InLoadOrderModuleList, and prints
//! each LDR_DATA_TABLE_ENTRY: base address, size, and BaseDllName.
//! No syscalls or Win32 APIs required — everything is in-process memory.
//!
//! LDR_DATA_TABLE_ENTRY (x64) offsets used:
//!   +0   InLoadOrderLinks           LIST_ENTRY (Flink/Blink 8+8)
//!   +48  DllBase                    PVOID
//!   +56  EntryPoint                 PVOID
//!   +64  SizeOfImage                ULONG
//!   +72  FullDllName                UNICODE_STRING (len u16 at+0, pad u16, pad u32, buf *u16 at+8)
//!   +88  BaseDllName                UNICODE_STRING (len u16 at+0, pad u16, pad u32, buf *u16 at+8)
//!
//! PEB (x64): ldr at offset 0x18
//! PEB_LDR_DATA: InLoadOrderModuleList at offset 0x10
//!
//! MITRE: T1057 (Process Discovery), T1016 (System Network Configuration Discovery)

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::mitre::Technique;

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1057", name: "Process Discovery",                       tactic: "Discovery" },
    Technique { id: "T1016", name: "System Network Configuration Discovery",  tactic: "Discovery" },
];

// PEB / LDR offsets (x64)
const PEB_LDR_OFFSET:               usize = 0x18; // PEB.Ldr
const LDR_INLOADORDER_OFFSET:       usize = 0x10; // PEB_LDR_DATA.InLoadOrderModuleList (LIST_ENTRY)
// LDR_DATA_TABLE_ENTRY field offsets
const LDTE_DLL_BASE:                usize = 48;
const LDTE_SIZE_OF_IMAGE:           usize = 64;  // ULONG
const LDTE_BASE_DLL_NAME_LEN:       usize = 88;  // UNICODE_STRING.Length (u16)
const LDTE_BASE_DLL_NAME_BUF:       usize = 96;  // UNICODE_STRING.Buffer (*u16) — offset 88+8

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(())  => {},
        Err(e)  => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    println!("{:<18} {:<12} {}", "Base", "Size", "Name");
    println!("{}", "------------------------------------------------------------");

    // Read PEB from gs:[0x60]
    let peb: usize;
    unsafe {
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nomem, nostack));
    }
    if peb == 0 { return Err("peb null"); }

    // PEB.Ldr
    let ldr = unsafe { core::ptr::read_unaligned((peb + PEB_LDR_OFFSET) as *const usize) };
    if ldr == 0 { return Err("ldr null"); }

    // Head of InLoadOrderModuleList (LIST_ENTRY inside PEB_LDR_DATA)
    let list_head = ldr + LDR_INLOADORDER_OFFSET;

    // First entry = Flink of list head
    let mut cur = unsafe { core::ptr::read_unaligned(list_head as *const usize) };

    let mut count = 0usize;
    let mut iter_guard = 0usize;

    loop {
        // Sentinel: back to the list head
        if cur == list_head || cur == 0 { break; }
        iter_guard += 1;
        if iter_guard > 1024 { break; } // defensive

        // InLoadOrderLinks is at offset 0 of LDR_DATA_TABLE_ENTRY,
        // so cur IS the entry pointer.
        let entry = cur;

        let dll_base  = unsafe { core::ptr::read_unaligned((entry + LDTE_DLL_BASE)      as *const usize) };
        let img_size  = unsafe { core::ptr::read_unaligned((entry + LDTE_SIZE_OF_IMAGE) as *const u32) };
        let name_len  = unsafe { core::ptr::read_unaligned((entry + LDTE_BASE_DLL_NAME_LEN) as *const u16) } as usize;
        let name_buf  = unsafe { core::ptr::read_unaligned((entry + LDTE_BASE_DLL_NAME_BUF) as *const usize) };

        // Convert UNICODE_STRING to ASCII
        let mut abuf = [0u8; 64];
        if name_buf != 0 && name_len > 0 {
            let char_count = (name_len / 2).min(63);
            let wide_slice = unsafe { core::slice::from_raw_parts(name_buf as *const u16, char_count) };
            let n = common::str_util::wide_to_ascii_buf(wide_slice, &mut abuf);
            let _ = n; // n stored implicitly via null terminator
        }
        let name_str = cstr_to_str(&abuf);

        println!("0x{:016x} {:<12} {}", dll_base, img_size, name_str);
        count += 1;

        // Advance: Flink is at offset 0 of the LIST_ENTRY = offset 0 of the entry
        cur = unsafe { core::ptr::read_unaligned(entry as *const usize) };
    }

    println!("");
    println!("[*] {} modules in current process", count);
    Ok(())
}

/// Interpret a null-terminated byte buffer as a &str (best-effort UTF-8).
fn cstr_to_str(buf: &[u8]) -> &str {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..len]).unwrap_or("?")
}
