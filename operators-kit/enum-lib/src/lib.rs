// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};
use alloc::string::String;

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1057", name: "Process Discovery", tactic: "Discovery" },
];

const TH32CS_SNAPMODULE:   u32 = 0x00000008u32;
const TH32CS_SNAPMODULE32: u32 = 0x00000010u32;

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

/// Extract a C string (up to null byte) from a byte slice as a borrowed slice.
fn cstr_from_buf(buf: &[u8]) -> &[u8] {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    &buf[..end]
}

fn parse_u32(s: &str) -> Option<u32> {
    let mut v: u32 = 0; let mut any = false;
    for b in s.bytes() {
        if !b.is_ascii_digit() { return None; }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u32)?;
        any = true;
    }
    if any { Some(v) } else { None }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let pid_s = String::from(parser.get_str());
    let pid_str = pid_s.as_str();
    if pid_str.is_empty() { return Err("usage: enum-lib <pid>"); }
    let pid: u32 = parse_u32(pid_str).ok_or("invalid pid")?;

    let snap = unsafe {
        create_toolhelp32_snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid,
        )
    }.map_err(|_| "snapshot failed")?;

    // INVALID_HANDLE_VALUE = !0usize
    if snap == !0usize {
        return Err("snapshot invalid");
    }

    // MODULEENTRY32A on x64 = 568 bytes (verified via windows-sys-0.52)
    // Layout (x64, 8-byte aligned):
    //   offset  0: dwSize     (u32)   — must be set to 568
    //   offset  4: th32ModuleID (u32)
    //   offset  8: th32ProcessID (u32)
    //   offset 12: GlblcntUsage (u32)
    //   offset 16: ProccntUsage (u32)
    //   offset 20: _pad (4 bytes)
    //   offset 24: modBaseAddr (*mut u8, 8 bytes)
    //   offset 32: modBaseSize (u32)
    //   offset 36: _pad (4 bytes)
    //   offset 40: hModule (8 bytes)
    //   offset 48: szModule ([u8; 256])  ends @ 304
    //   offset 304: szExePath ([u8; 260]) ends @ 564
    //   tail align to 8 → 568
    const MODULEENTRY32A_SIZE: usize = 568;
    let mut entry = [0u8; MODULEENTRY32A_SIZE];
    // Set dwSize = 568 (Module32FirstA validates against sizeof(MODULEENTRY32A))
    let dw_size: u32 = MODULEENTRY32A_SIZE as u32;
    entry[0..4].copy_from_slice(&dw_size.to_le_bytes());

    println!("LOADED MODULES for PID {}:", pid);
    println!("{}", "--------------------------------------------");

    let mut count: u32 = 0;
    let ok = unsafe { module32_first_a(snap, entry.as_mut_ptr()) }
        .map_err(|_| "mod first")?;

    if ok == 0 {
        unsafe { let _ = close_handle(snap); };
        return Err("no modules");
    }

    loop {
        // modBaseSize at offset 32 (u32)
        let base_size = u32::from_le_bytes([entry[32], entry[33], entry[34], entry[35]]);
        // szModule at offset 48 (max 256 bytes)
        let mod_name_bytes = cstr_from_buf(&entry[48..304]);
        // szExePath at offset 304 (max 260 bytes)
        let exe_path_bytes = cstr_from_buf(&entry[304..564]);

        let mod_name = core::str::from_utf8(mod_name_bytes).unwrap_or("?");
        let exe_path = core::str::from_utf8(exe_path_bytes).unwrap_or("?");

        println!("  [0x{:08X}] {} -> {}", base_size, mod_name, exe_path);
        count += 1;

        // Reset dwSize for next call
        entry[0..4].copy_from_slice(&dw_size.to_le_bytes());

        let next_ok = unsafe { module32_next_a(snap, entry.as_mut_ptr()) }
            .unwrap_or(0);
        if next_ok == 0 {
            break;
        }
    }

    unsafe { let _ = close_handle(snap); };
    println!("  {} module(s) listed", count);
    Ok(())
}
