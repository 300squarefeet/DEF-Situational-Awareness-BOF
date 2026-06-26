// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Find potential DLL sideloading opportunities in a process's loaded modules.
//! Modules NOT loaded from System32 / SysWOW64 / Windows dirs are flagged.
//! Args: <pid>
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1574.002", name: "DLL Side-Loading", tactic: "Defense Evasion" },
];

const TH32CS_SNAPMODULE:   u32 = 0x00000008;
const TH32CS_SNAPMODULE32: u32 = 0x00000010;

dfr_fn!(
    create_toolhelp32_snapshot(flags: u32, pid: u32) -> usize,
    module = "kernel32.dll",
    api    = "CreateToolhelp32Snapshot"
);

dfr_fn!(
    module32_first_a(snap: usize, entry: *mut u8) -> i32,
    module = "kernel32.dll",
    api    = "Module32FirstA"
);

dfr_fn!(
    module32_next_a(snap: usize, entry: *mut u8) -> i32,
    module = "kernel32.dll",
    api    = "Module32NextA"
);

dfr_fn!(
    close_handle(h: usize) -> i32,
    module = "kernel32.dll",
    api    = "CloseHandle"
);

/// Parse a decimal u32 from a &str.
fn parse_u32(s: &str) -> Option<u32> {
    let mut acc: u32 = 0;
    if s.is_empty() { return None; }
    for &b in s.as_bytes() {
        let d = b.wrapping_sub(b'0');
        if d > 9 { return None; }
        acc = acc.checked_mul(10)?.checked_add(d as u32)?;
    }
    Some(acc)
}

/// Return the length of a NUL-terminated slice (capped at `cap`).
fn strlen_capped(buf: &[u8], cap: usize) -> usize {
    buf.iter().take(cap).position(|&b| b == 0).unwrap_or(cap)
}

/// Case-insensitive contains for ASCII: does `haystack` contain `needle` (lowercase)?
fn ascii_contains_lower(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() { return false; }
    'outer: for start in 0..=(haystack.len() - needle.len()) {
        for (i, &nb) in needle.iter().enumerate() {
            let hb = haystack[start + i].to_ascii_lowercase();
            if hb != nb { continue 'outer; }
        }
        return true;
    }
    false
}

/// Returns true if the path lives in a system directory (system32, syswow64, windows\system).
fn is_system_path(path: &[u8]) -> bool {
    ascii_contains_lower(path, b"\\system32\\")
        || ascii_contains_lower(path, b"\\syswow64\\")
        || ascii_contains_lower(path, b"\\windows\\system\\")
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {}
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let pid_s = String::from(parser.get_str());
    let pid_str = pid_s.as_str();
    if pid_str.is_empty() { return Err("usage: enum-dll-sideloading <pid>"); }
    let pid = parse_u32(pid_str).ok_or("invalid pid")?;

    let snap = unsafe {
        create_toolhelp32_snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    }.map_err(|_| "snapshot failed")?;

    if snap == 0 || snap == !0usize {
        return Err("snapshot invalid");
    }

    // MODULEENTRY32A on x64 = 568 bytes (verified via windows-sys-0.52).
    // dwSize at offset 0 (u32), szExePath at offset 304 ([u8; 260]), ends @ 564,
    // struct tail-aligned to 8 → 568. Module32FirstA validates dwSize strictly.
    const MODULEENTRY32A_SIZE: usize = 568;
    let mut entry = [0u8; MODULEENTRY32A_SIZE];
    // Set dwSize = 568 LE
    let sz_bytes = (MODULEENTRY32A_SIZE as u32).to_le_bytes();
    entry[0] = sz_bytes[0];
    entry[1] = sz_bytes[1];
    entry[2] = sz_bytes[2];
    entry[3] = sz_bytes[3];

    let mut found: u32 = 0;
    println!("{}", obf!("[*] Modules not in system directories (potential sideload targets):"));

    let mut ok = unsafe { module32_first_a(snap, entry.as_mut_ptr()) }
        .unwrap_or(0);

    while ok != 0 {
        // szExePath at offset 304, length 260
        let path_bytes = &entry[304..304 + 260];
        let path_len = strlen_capped(path_bytes, 260);
        let path = &path_bytes[..path_len];

        if !is_system_path(path) && path_len > 0 {
            // Print as ASCII — BOF output is ASCII-safe
            let mut line = [0u8; 280];
            let prefix = b"  [sideload?] ";
            line[..prefix.len()].copy_from_slice(prefix);
            let copy_len = path_len.min(260);
            line[prefix.len()..prefix.len() + copy_len].copy_from_slice(&path[..copy_len]);
            // println! needs &str — build one from the stack buffer
            if let Ok(s) = core::str::from_utf8(&line[..prefix.len() + copy_len]) {
                println!("{}", s);
            }
            found += 1;
        }

        // Reset dwSize for next call
        entry[0] = sz_bytes[0];
        entry[1] = sz_bytes[1];
        entry[2] = sz_bytes[2];
        entry[3] = sz_bytes[3];

        ok = unsafe { module32_next_a(snap, entry.as_mut_ptr()) }
            .unwrap_or(0);
    }

    unsafe { let _ = close_handle(snap); };

    if found == 0 {
        println!("{}", obf!("  (none — all modules in system directories)"));
    } else {
        println!("{} potential target(s).", found);
    }
    Ok(())
}
