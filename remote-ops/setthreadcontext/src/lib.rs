// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Enumerate thread IDs for a process and show first thread's context RIP.
//! Args: <pid>
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::string::String;
use core::ffi::c_void;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1055.003", name: "Thread Execution Hijacking", tactic: "Defense Evasion" },
];

const TH32CS_SNAPTHREAD:     u32 = 0x00000004;
const THREAD_GET_CONTEXT:    u32 = 0x0008;
const THREAD_SUSPEND_RESUME: u32 = 0x0002;

// x64 CONTEXT: 1232 bytes total, RIP at offset 248, ContextFlags at offset 48
#[cfg(target_arch = "x86_64")]
const CONTEXT_FULL: u32  = 0x10000B;
#[cfg(target_arch = "x86_64")]
const CONTEXT_SIZE: usize = 1232;
#[cfg(target_arch = "x86_64")]
const CTX_FLAGS_OFF: usize = 48;
#[cfg(target_arch = "x86_64")]
const RIP_OFFSET: usize   = 248;

dfr_fn!(
    create_toolhelp32_snapshot(flags: u32, pid: u32) -> *mut c_void,
    module = "kernel32.dll", api = "CreateToolhelp32Snapshot"
);
dfr_fn!(
    thread32_first(snap: *mut c_void, te: *mut u8) -> i32,
    module = "kernel32.dll", api = "Thread32First"
);
dfr_fn!(
    thread32_next(snap: *mut c_void, te: *mut u8) -> i32,
    module = "kernel32.dll", api = "Thread32Next"
);
dfr_fn!(
    close_handle(h: *mut c_void) -> i32,
    module = "kernel32.dll", api = "CloseHandle"
);

#[cfg(target_arch = "x86_64")]
dfr_fn!(
    open_thread(access: u32, inherit: i32, tid: u32) -> *mut c_void,
    module = "kernel32.dll", api = "OpenThread"
);
#[cfg(target_arch = "x86_64")]
dfr_fn!(
    get_thread_context(h: *mut c_void, ctx: *mut u8) -> i32,
    module = "kernel32.dll", api = "GetThreadContext"
);

// THREADENTRY32: dwSize(u32@0), cntUsage(u32@4), th32ThreadID(u32@8),
//   th32OwnerProcessID(u32@12), stride=28
const TE32_SIZE: u32 = 28;

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
    if pid_str.is_empty() { return Err("usage: setthreadcontext <pid>"); }

    let mut pid: u32 = 0;
    for b in pid_str.bytes() {
        if !b.is_ascii_digit() { return Err("invalid pid"); }
        pid = pid.checked_mul(10).ok_or("pid overflow")?
            .checked_add((b - b'0') as u32).ok_or("pid overflow")?;
    }

    let snap = unsafe {
        create_toolhelp32_snapshot(TH32CS_SNAPTHREAD, 0)
    }.map_err(|_| "snapshot failed")?;
    if snap.is_null() { return Err("snapshot invalid"); }

    let mut te = [0u8; 32];
    unsafe { core::ptr::write_unaligned(te.as_mut_ptr() as *mut u32, TE32_SIZE) };
    let ok = unsafe { thread32_first(snap, te.as_mut_ptr()) }.unwrap_or(0);
    if ok == 0 {
        unsafe { let _ = close_handle(snap); };
        return Err("no threads");
    }

    println!("Threads for PID {}:", pid);
    let mut count = 0u32;
    loop {
        let tid   = unsafe { core::ptr::read_unaligned(te.as_ptr().add(8) as *const u32) };
        let owner = unsafe { core::ptr::read_unaligned(te.as_ptr().add(12) as *const u32) };
        if owner == pid {
            println!("  TID={}", tid);
            #[cfg(target_arch = "x86_64")]
            if count == 0 {
                // Optionally show RIP of first thread
                let h_thr = unsafe {
                    open_thread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, 0, tid)
                }.unwrap_or(core::ptr::null_mut());
                if !h_thr.is_null() {
                    let mut ctx = [0u8; CONTEXT_SIZE];
                    unsafe {
                        core::ptr::write_unaligned(
                            ctx.as_mut_ptr().add(CTX_FLAGS_OFF) as *mut u32,
                            CONTEXT_FULL,
                        );
                    }
                    let ctx_ok = unsafe { get_thread_context(h_thr, ctx.as_mut_ptr()) }
                        .unwrap_or(0);
                    if ctx_ok != 0 {
                        let rip = unsafe {
                            core::ptr::read_unaligned(ctx.as_ptr().add(RIP_OFFSET) as *const u64)
                        };
                        println!("    RIP=0x{:016X}", rip);
                    }
                    unsafe { let _ = close_handle(h_thr); };
                }
            }
            count += 1;
        }
        if count >= 64 { println!("  (truncated at 64)"); break; }
        unsafe { core::ptr::write_unaligned(te.as_mut_ptr() as *mut u32, TE32_SIZE) };
        if unsafe { thread32_next(snap, te.as_mut_ptr()) }.unwrap_or(0) == 0 { break; }
    }

    unsafe { let _ = close_handle(snap); };
    println!("{} thread(s) found for PID {}", count, pid);
    Ok(())
}
