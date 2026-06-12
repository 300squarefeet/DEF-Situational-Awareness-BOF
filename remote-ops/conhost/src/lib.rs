// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Find conhost.exe PIDs, optionally filtered by parent PID.
//! Args: [parent_pid]
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1057", name: "Process Discovery", tactic: "Discovery" },
];

const TH32CS_SNAPPROCESS: u32 = 0x00000002;

dfr_fn!(
    create_toolhelp32_snapshot(flags: u32, pid: u32) -> usize,
    module = "kernel32.dll",
    api    = "CreateToolhelp32Snapshot"
);

dfr_fn!(
    process32_first_a(snap: usize, entry: *mut u8) -> i32,
    module = "kernel32.dll",
    api    = "Process32FirstA"
);

dfr_fn!(
    process32_next_a(snap: usize, entry: *mut u8) -> i32,
    module = "kernel32.dll",
    api    = "Process32NextA"
);

dfr_fn!(
    close_handle(h: usize) -> i32,
    module = "kernel32.dll",
    api    = "CloseHandle"
);

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
    let filter_s = String::from(parser.get_str());
    let filter_pid: Option<u32> = if filter_s.is_empty() {
        None
    } else {
        Some(parse_u32(filter_s.as_str()).ok_or("invalid pid arg")?)
    };

    let snap = unsafe { create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|_| "snap resolve")?;
    if snap == !0usize { return Err("snapshot failed"); }

    // PROCESSENTRY32A = 296 bytes
    // dwSize @ 0, th32ProcessID @ 8 (u32), th32ParentProcessID @ 32 (u32), szExeFile @ 44 ([u8;260])
    let mut entry = [0u8; 296];
    let dw: u32 = 296;
    entry[0..4].copy_from_slice(&dw.to_le_bytes());

    let ok = unsafe { process32_first_a(snap, entry.as_mut_ptr()) }
        .map_err(|_| "proc first resolve")?;
    if ok == 0 {
        unsafe { let _ = close_handle(snap); };
        return Err("no processes");
    }

    obf! { let target = "conhost.exe"; }
    let target_bytes = target.as_bytes();
    let mut found: u32 = 0;

    loop {
        let pid = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
        let ppid = u32::from_le_bytes([entry[32], entry[33], entry[34], entry[35]]);
        let name = &entry[44..44+260];
        let name_len = name.iter().position(|&b| b == 0).unwrap_or(260);
        let name_s = &name[..name_len];

        // Case-insensitive compare to "conhost.exe" (11 bytes)
        if name_len == target_bytes.len() {
            let mut matches = true;
            for (a, b) in name_s.iter().zip(target_bytes.iter()) {
                if a.to_ascii_lowercase() != b.to_ascii_lowercase() {
                    matches = false;
                    break;
                }
            }
            if matches {
                if filter_pid.map_or(true, |fp| fp == ppid) {
                    println!("  conhost.exe PID={} parentPID={}", pid, ppid);
                    found += 1;
                }
            }
        }

        entry[0..4].copy_from_slice(&dw.to_le_bytes());
        let next = unsafe { process32_next_a(snap, entry.as_mut_ptr()) }
            .unwrap_or(0);
        if next == 0 { break; }
    }

    unsafe { let _ = close_handle(snap); };
    println!("[+] {} conhost.exe instance(s) found", found);
    Ok(())
}
