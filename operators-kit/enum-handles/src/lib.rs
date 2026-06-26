// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use alloc::vec::Vec;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1106", name: "Native API", tactic: "Execution" },
];

const SYSTEM_HANDLE_INFORMATION: u32 = 16u32;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
const STATUS_SUCCESS: i32 = 0i32;

#[cfg(target_arch = "x86_64")]
dfr_fn!(
    nt_query_system_information(
        info_class: u32,
        buf: *mut u8,
        buf_len: u32,
        ret_len: *mut u32
    ) -> i32,
    module = "ntdll.dll",
    api    = "NtQuerySystemInformation"
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

#[cfg(target_arch = "x86_64")]
fn run_impl(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let pid_s = String::from(parser.get_str());
    let pid_str = pid_s.as_str();
    if pid_str.is_empty() { return Err("usage: enum-handles <pid>"); }
    let pid: u32 = parse_u32(pid_str).ok_or("invalid pid")?;

    let mut size: usize = 256 * 1024;
    let max_size: usize = 64 * 1024 * 1024;

    loop {
        if size > max_size {
            return Err("buf too large");
        }
        let mut buf: Vec<u8> = Vec::with_capacity(size);
        buf.resize(size, 0u8);

        let mut ret_len: u32 = 0;
        let status = unsafe {
            nt_query_system_information(
                SYSTEM_HANDLE_INFORMATION,
                buf.as_mut_ptr(),
                size as u32,
                &mut ret_len,
            )
        }.map_err(|_| "query failed")?;

        if status == STATUS_INFO_LENGTH_MISMATCH {
            size = if ret_len as usize > size { ret_len as usize + 4096 } else { size * 2 };
            continue;
        }

        if status != STATUS_SUCCESS {
            return Err("query status");
        }

        // Read NumberOfHandles at offset 0 (u32)
        if buf.len() < 8 {
            return Err("buf short");
        }
        let n_handles = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

        println!("OPEN HANDLES for PID {}  ({} total system handles):", pid, n_handles);
        println!("{}", "----------------------------------------------------");

        let mut matched: u32 = 0;
        for i in 0..n_handles {
            // stride = 24 bytes; array starts at offset 8
            let entry_base = 8 + i * 24;
            if entry_base + 24 > buf.len() {
                break;
            }
            // UniqueProcessId at offset 0 (u16)
            let uid = u16::from_le_bytes([buf[entry_base], buf[entry_base + 1]]) as u32;
            if uid != pid {
                continue;
            }
            // HandleValue at offset 6 (u16)
            let handle_val = u16::from_le_bytes([buf[entry_base + 6], buf[entry_base + 7]]);
            // Object ptr at offset 8 (u64)
            let obj = u64::from_le_bytes([
                buf[entry_base + 8],  buf[entry_base + 9],
                buf[entry_base + 10], buf[entry_base + 11],
                buf[entry_base + 12], buf[entry_base + 13],
                buf[entry_base + 14], buf[entry_base + 15],
            ]);
            // GrantedAccess at offset 16 (u32)
            let access = u32::from_le_bytes([
                buf[entry_base + 16], buf[entry_base + 17],
                buf[entry_base + 18], buf[entry_base + 19],
            ]);
            println!(
                "  handle=0x{:04X} access=0x{:08X} obj=0x{:016X}",
                handle_val, access, obj
            );
            matched += 1;
        }

        println!("  {} handles matched PID {}", matched, pid);
        return Ok(());
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    #[cfg(target_arch = "x86_64")]
    { return run_impl(parser); }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = parser; return Err("x64 only"); }
}
