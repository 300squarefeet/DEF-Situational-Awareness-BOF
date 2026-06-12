// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! List open handles of a process by PID via NtQuerySystemInformation.
//! Args: <pid>
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use alloc::vec::Vec;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1106", name: "Native API", tactic: "Execution" },
];

const SYSTEM_HANDLE_INFORMATION: u32 = 0x10;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;

// SYSTEM_HANDLE_TABLE_ENTRY_INFO (stride = 24 bytes with padding):
// UniqueProcessId(u16@0), CreatorBackTraceIndex(u16@2), ObjectTypeIndex(u8@4),
// HandleAttributes(u8@5), HandleValue(u16@6), Object(*mut c_void @8), GrantedAccess(u32@16)
const ENTRY_STRIDE: usize = 24;
const ENTRY_PID_OFF: usize = 0;
const ENTRY_TYPE_OFF: usize = 4;
const ENTRY_HANDLE_OFF: usize = 6;
const ENTRY_OBJ_OFF: usize = 8;

dfr_fn!(
    nt_query_system_information(
        class: u32,
        buf: *mut u8,
        len: u32,
        ret_len: *mut u32,
    ) -> i32,
    module = "ntdll.dll",
    api    = "NtQuerySystemInformation"
);

fn parse_u32(s: &str) -> Option<u32> {
    let mut v: u32 = 0;
    let mut any = false;
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
    let pid_s = pid_s.as_str();
    if pid_s.is_empty() {
        return Err("usage: processlisthandles <pid>");
    }
    let target_pid = parse_u32(pid_s).ok_or("invalid pid")? as u16;

    // Grow buffer until NtQuerySystemInformation succeeds
    let mut buf_size: usize = 65536;
    let mut buf: Vec<u8> = Vec::new();
    let mut ret_len: u32 = 0;

    loop {
        buf.resize(buf_size, 0);
        let rc = unsafe {
            nt_query_system_information(
                SYSTEM_HANDLE_INFORMATION,
                buf.as_mut_ptr(),
                buf_size as u32,
                &mut ret_len,
            )
        }.map_err(|_| "query resolve")?;

        if rc == STATUS_INFO_LENGTH_MISMATCH {
            buf_size = if ret_len > 0 {
                (ret_len as usize).saturating_add(4096)
            } else {
                buf_size.saturating_mul(2)
            };
            if buf_size > 64 * 1024 * 1024 {
                return Err("buffer too large");
            }
            continue;
        }
        if rc < 0 {
            return Err("query failed");
        }
        break;
    }

    // First u32 = NumberOfHandles
    if buf.len() < 4 { return Err("buf too small"); }
    let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    obf! { let hdr = "handles for pid"; }
    println!("[*] {} {} ({} total):", hdr, target_pid, count);

    let data_start = 8; // u32 count + u32 pad
    let mut found = 0u32;
    for i in 0..count {
        let off = data_start + i * ENTRY_STRIDE;
        if off + ENTRY_STRIDE > buf.len() { break; }
        let pid = u16::from_le_bytes([buf[off + ENTRY_PID_OFF], buf[off + ENTRY_PID_OFF + 1]]);
        if pid != target_pid { continue; }
        let ty    = buf[off + ENTRY_TYPE_OFF];
        let hval  = u16::from_le_bytes([buf[off + ENTRY_HANDLE_OFF], buf[off + ENTRY_HANDLE_OFF + 1]]);
        let obj_lo = u32::from_le_bytes([
            buf[off + ENTRY_OBJ_OFF],
            buf[off + ENTRY_OBJ_OFF + 1],
            buf[off + ENTRY_OBJ_OFF + 2],
            buf[off + ENTRY_OBJ_OFF + 3],
        ]);
        println!("  handle=0x{:04x}  type={:3}  obj=0x{:08x}", hval, ty, obj_lo);
        found += 1;
    }

    obf! { let done = "found handles"; }
    println!("[+] {} {}", found, done);
    Ok(())
}
