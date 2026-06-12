// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Kill a process by PID or name.
//! Args: <pid_or_name>
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1562.001", name: "Disable or Modify Tools", tactic: "Defense Evasion" },
];

const PROCESS_TERMINATE: u32     = 0x0001;
const TH32CS_SNAPPROCESS: u32    = 0x00000002;
const INVALID_HANDLE: usize      = !0usize;

// PROCESSENTRY32A layout (296 bytes total):
// dwSize(u32@0), cntUsage(u32@4), th32ProcessID(u32@8), th32DefaultHeapID(usize@16),
// th32ModuleID(u32@24), cntThreads(u32@28), th32ParentProcessID(u32@32),
// pcPriClassBase(i32@36), dwFlags(u32@40), szExeFile([u8;260]@44)
// On x64 sizeof(PROCESSENTRY32A) = 304 (ULONG_PTR th32DefaultHeapID introduces
// 4-byte pad after th32ProcessID, taking the struct from 296 to 304).
// Process32FirstA validates dwSize == sizeof(PROCESSENTRY32A) and returns
// ERROR_BAD_LENGTH otherwise; a too-small buffer would also risk overflow.
const PROCESSENTRY32A_SIZE: usize = 304;
const PID_OFFSET: usize           = 8;
const NAME_OFFSET: usize          = 44;

dfr_fn!(
    open_process(access: u32, inherit: i32, pid: u32) -> usize,
    module = "kernel32.dll",
    api    = "OpenProcess"
);
dfr_fn!(
    terminate_process(proc: usize, exit_code: u32) -> i32,
    module = "kernel32.dll",
    api    = "TerminateProcess"
);
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
    let arg = String::from(parser.get_str());
    let arg = arg.as_str();
    if arg.is_empty() {
        return Err("usage: processdestroy <pid_or_name>");
    }

    let pid: u32 = if let Some(n) = parse_u32(arg) {
        n
    } else {
        find_pid_by_name(arg)?
    };

    let h = unsafe { open_process(PROCESS_TERMINATE, 0, pid) }
        .map_err(|_| "open failed")?;
    if h == 0 || h == INVALID_HANDLE {
        return Err("open process failed");
    }

    let rc = unsafe { terminate_process(h, 1) }.map_err(|_| "terminate resolve")?;
    unsafe { let _ = close_handle(h); };

    if rc == 0 {
        return Err("terminate failed");
    }
    obf! { let ok = "process terminated"; }
    println!("[+] {} (pid={})", ok, pid);
    Ok(())
}

fn find_pid_by_name(name: &str) -> Result<u32, &'static str> {
    let snap = unsafe { create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|_| "snapshot resolve")?;
    if snap == 0 || snap == INVALID_HANDLE {
        return Err("snapshot failed");
    }

    let mut entry = [0u8; PROCESSENTRY32A_SIZE];
    // Set dwSize at offset 0
    let size_bytes = (PROCESSENTRY32A_SIZE as u32).to_le_bytes();
    entry[0] = size_bytes[0];
    entry[1] = size_bytes[1];
    entry[2] = size_bytes[2];
    entry[3] = size_bytes[3];

    let mut rc = unsafe { process32_first_a(snap, entry.as_mut_ptr()) }
        .map_err(|_| "enum failed")?;

    let mut found_pid: Option<u32> = None;

    while rc != 0 && found_pid.is_none() {
        let pid_bytes = &entry[PID_OFFSET..PID_OFFSET + 4];
        let pid = u32::from_le_bytes([pid_bytes[0], pid_bytes[1], pid_bytes[2], pid_bytes[3]]);

        let name_bytes = &entry[NAME_OFFSET..NAME_OFFSET + 260];
        let nul = name_bytes.iter().position(|&b| b == 0).unwrap_or(260);
        let proc_name = &name_bytes[..nul];

        if proc_name.len() == name.len() {
            let match_ = proc_name.iter().zip(name.bytes())
                .all(|(&a, b)| a.eq_ignore_ascii_case(&b));
            if match_ {
                found_pid = Some(pid);
            }
        }

        if found_pid.is_none() {
            // Reset dwSize for next call
            entry = [0u8; PROCESSENTRY32A_SIZE];
            entry[0] = size_bytes[0];
            entry[1] = size_bytes[1];
            entry[2] = size_bytes[2];
            entry[3] = size_bytes[3];
            rc = unsafe { process32_next_a(snap, entry.as_mut_ptr()) }
                .map_err(|_| "enum failed")?;
        }
    }

    unsafe { let _ = close_handle(snap); };

    found_pid.ok_or("process not found")
}
