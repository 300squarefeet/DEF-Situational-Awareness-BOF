// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Original C: TrustedSec/cs-remote-ops/suspendresume
//
//! Suspend or resume a target process via indirect syscalls.
//!
//! Args: <pid:u32> <action: "suspend"|"resume">
//!
//! Syscalls used (all indirect, ntdll-resident gadget):
//!   - NtOpenProcess      (PROCESS_SUSPEND_RESUME = 0x0800)
//!   - NtSuspendProcess   (1-arg)  | NtResumeProcess (1-arg)
//!   - NtClose            (1-arg)

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1055", name: "Process Injection (precondition)", tactic: "Defense Evasion" },
];

const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
const STATUS_SUCCESS: i32 = 0;

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: usize,
    object_name: usize,
    attributes: u32,
    security_descriptor: usize,
    security_quality_of_service: usize,
}

#[repr(C)]
struct ClientId { unique_process: usize, unique_thread: usize }

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let pid_str = String::from(parser.get_str());
    let action  = String::from(parser.get_str());
    let pid_str = pid_str.as_str();
    let action  = action.as_str();

    if pid_str.is_empty() || action.is_empty() {
        return Err("usage: suspendresume <pid> <suspend|resume>");
    }
    let pid: u32 = parse_u32(pid_str).ok_or("invalid pid")?;

    let suspend = if action.eq_ignore_ascii_case("suspend") { true }
                  else if action.eq_ignore_ascii_case("resume") { false }
                  else { return Err("action must be 'suspend' or 'resume'"); };

    use common::syscalls::{SyscallEntry, resolve, do_syscall4};

    // -- Open target process
    static OPEN_ENTRY: SyscallEntry = SyscallEntry::new();
    const OPEN_HASH: u32 = common::hash::djb2(b"NtOpenProcess");
    let (open_ssn, open_addr) = unsafe { resolve(&OPEN_ENTRY, OPEN_HASH) }
        .map_err(|_| "resolve")?;

    let oa = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0, object_name: 0, attributes: 0,
        security_descriptor: 0, security_quality_of_service: 0,
    };
    let cid = ClientId { unique_process: pid as usize, unique_thread: 0 };
    let mut h_proc: usize = 0;
    let status = unsafe {
        do_syscall4(
            &mut h_proc as *mut usize as usize,
            PROCESS_SUSPEND_RESUME as usize,
            &oa as *const ObjectAttributes as usize,
            &cid as *const ClientId as usize,
            open_ssn, open_addr,
        )
    };
    if status != STATUS_SUCCESS || h_proc == 0 {
        return Err("proc open failed");
    }

    // -- Suspend or resume (1-arg). do_syscall4 with the trailing 3 args zero.
    let api_hash: u32 = if suspend {
        common::hash::djb2(b"NtSuspendProcess")
    } else {
        common::hash::djb2(b"NtResumeProcess")
    };
    static ACT_ENTRY: SyscallEntry = SyscallEntry::new();
    let (act_ssn, act_addr) = unsafe { resolve(&ACT_ENTRY, api_hash) }
        .map_err(|_| "resolve")?;
    let st2 = unsafe { do_syscall4(h_proc, 0, 0, 0, act_ssn, act_addr) };

    // -- Close handle
    static CLOSE_ENTRY: SyscallEntry = SyscallEntry::new();
    const CLOSE_HASH: u32 = common::hash::djb2(b"NtClose");
    if let Ok((c_ssn, c_addr)) = unsafe { resolve(&CLOSE_ENTRY, CLOSE_HASH) } {
        let _ = unsafe { do_syscall4(h_proc, 0, 0, 0, c_ssn, c_addr) };
    }

    if st2 != STATUS_SUCCESS {
        return Err("suspend/resume failed");
    }
    println!("[+] pid {} {}ed", pid, if suspend { "suspend" } else { "resum" });
    Ok(())
}

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
