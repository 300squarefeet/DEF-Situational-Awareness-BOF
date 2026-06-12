// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Shutdown, reboot, or logoff via ExitWindowsEx after acquiring SE_SHUTDOWN_NAME.
//! Args: reboot | shutdown | logoff
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1529", name: "System Shutdown/Reboot", tactic: "Impact" },
];

const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const TOKEN_QUERY:             u32 = 0x0008;
const SE_PRIVILEGE_ENABLED:    u32 = 0x00000002;

const EWX_LOGOFF:   u32 = 0;
const EWX_SHUTDOWN: u32 = 1;
const EWX_REBOOT:   u32 = 2;
const EWX_FORCE:    u32 = 4;

// TOKEN_PRIVILEGES layout: PrivilegeCount(u32@0), [then LUID_AND_ATTRIBUTES]
// LUID_AND_ATTRIBUTES: LowPart(u32@4), HighPart(i32@8), Attributes(u32@12) — 16 bytes total struct
const TOKEN_PRIVILEGES_SIZE: usize = 16;

dfr_fn!(
    get_current_process() -> usize,
    module = "kernel32.dll",
    api    = "GetCurrentProcess"
);
dfr_fn!(
    open_process_token(proc: usize, access: u32, token: *mut usize) -> i32,
    module = "advapi32.dll",
    api    = "OpenProcessToken"
);
dfr_fn!(
    lookup_privilege_value_a(sys: *const i8, name: *const i8, luid: *mut u8) -> i32,
    module = "advapi32.dll",
    api    = "LookupPrivilegeValueA"
);
dfr_fn!(
    adjust_token_privileges(
        token: usize, disable_all: i32,
        new_state: *mut u8, buf_len: u32,
        prev_state: *mut u8, ret_len: *mut u32,
    ) -> i32,
    module = "advapi32.dll",
    api    = "AdjustTokenPrivileges"
);
dfr_fn!(
    exit_windows_ex(flags: u32, reason: u32) -> i32,
    module = "user32.dll",
    api    = "ExitWindowsEx"
);
dfr_fn!(
    close_handle(h: usize) -> i32,
    module = "kernel32.dll",
    api    = "CloseHandle"
);

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
    let action = String::from(parser.get_str());
    let action = action.as_str();
    if action.is_empty() {
        return Err("usage: shutdown <reboot|shutdown|logoff>");
    }

    let flags: u32 = if action.eq_ignore_ascii_case("reboot") {
        EWX_REBOOT | EWX_FORCE
    } else if action.eq_ignore_ascii_case("shutdown") {
        EWX_SHUTDOWN | EWX_FORCE
    } else if action.eq_ignore_ascii_case("logoff") {
        EWX_LOGOFF | EWX_FORCE
    } else {
        return Err("unknown action (use reboot/shutdown/logoff)");
    };

    // Acquire SeShutdownPrivilege
    let proc_handle = unsafe { get_current_process() }.map_err(|_| "get proc resolve")?;
    if proc_handle == 0 { return Err("get proc failed"); }

    let mut token: usize = 0;
    let rc = unsafe {
        open_process_token(proc_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token)
    }.map_err(|_| "open token resolve")?;
    if rc == 0 || token == 0 { return Err("open token failed"); }

    // "SeShutdownPrivilege" NUL terminated
    let priv_name: &[u8] = b"SeShutdownPrivilege\0";
    let mut luid = [0u8; 8]; // LUID = LowPart(u32) + HighPart(i32)
    let rc2 = unsafe {
        lookup_privilege_value_a(core::ptr::null(), priv_name.as_ptr() as *const i8, luid.as_mut_ptr())
    }.map_err(|_| "lookup priv resolve")?;
    if rc2 == 0 {
        unsafe { let _ = close_handle(token); };
        return Err("lookup priv failed");
    }

    // TOKEN_PRIVILEGES: PrivilegeCount(u32) + LUID(8 bytes) + Attributes(u32) = 16 bytes
    let mut tp = [0u8; TOKEN_PRIVILEGES_SIZE];
    tp[0..4].copy_from_slice(&1u32.to_le_bytes()); // PrivilegeCount = 1
    tp[4..12].copy_from_slice(&luid);               // LUID (LowPart + HighPart)
    tp[12..16].copy_from_slice(&SE_PRIVILEGE_ENABLED.to_le_bytes()); // Attributes

    let rc3 = unsafe {
        adjust_token_privileges(token, 0, tp.as_mut_ptr(), TOKEN_PRIVILEGES_SIZE as u32,
            core::ptr::null_mut(), core::ptr::null_mut())
    }.map_err(|_| "adjust priv resolve")?;
    unsafe { let _ = close_handle(token); };
    if rc3 == 0 { return Err("adjust priv failed"); }

    // 0x00040000 = SHTDN_REASON_MAJOR_OTHER
    let rc4 = unsafe { exit_windows_ex(flags, 0x00040000) }.map_err(|_| "exit windows resolve")?;
    if rc4 == 0 { return Err("exit windows failed"); }

    obf! { let ok = "initiated"; }
    println!("[+] {} {}", action, ok);
    Ok(())
}
