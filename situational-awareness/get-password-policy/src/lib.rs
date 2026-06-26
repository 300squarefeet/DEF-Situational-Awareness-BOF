// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Domain password policy via NetUserModalsGet (level 0).
//! Args: [domain]
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::string::String;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1201", name: "Password Policy Discovery", tactic: "Discovery" },
];

const NERR_SUCCESS: u32 = 0;

// USER_MODALS_INFO_0
#[repr(C)]
struct UserModalsInfo0 {
    usrmod0_min_passwd_len:  u32,
    usrmod0_max_passwd_age:  u32,
    usrmod0_min_passwd_age:  u32,
    usrmod0_force_logoff:    u32,
    usrmod0_password_hist_len: u32,
}

dfr_fn!(
    net_user_modals_get(
        server_name: *const u16,
        level: u32,
        buf_ptr: *mut *mut u8,
    ) -> u32,
    module = "netapi32.dll",
    api    = "NetUserModalsGet"
);

dfr_fn!(
    net_api_buffer_free(buffer: *mut u8) -> u32,
    module = "netapi32.dll",
    api    = "NetApiBufferFree"
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
    let domain_s = String::from(parser.get_str());

    let mut domain_wide = [0u16; 256];
    let server_ptr: *const u16 = if domain_s.is_empty() {
        core::ptr::null()
    } else {
        let dlen = domain_s.len().min(255);
        for (i, b) in domain_s.as_bytes()[..dlen].iter().enumerate() {
            domain_wide[i] = *b as u16;
        }
        domain_wide.as_ptr()
    };

    let mut buf: *mut u8 = core::ptr::null_mut();
    let rc = unsafe {
        net_user_modals_get(server_ptr, 0, &mut buf)
    }.map_err(|_| "query failed")?;

    if rc != NERR_SUCCESS || buf.is_null() {
        return Err("query failed");
    }

    let info = unsafe { &*(buf as *const UserModalsInfo0) };

    println!("Password Policy");
    println!("{}", "--------------------------------------------");
    println!("  Min Password Length   : {}", info.usrmod0_min_passwd_len);
    println!("  Max Password Age (s)  : {}", info.usrmod0_max_passwd_age);
    println!("  Min Password Age (s)  : {}", info.usrmod0_min_passwd_age);
    println!("  Force Logoff (s)      : {}", info.usrmod0_force_logoff);
    println!("  Password History Len  : {}", info.usrmod0_password_hist_len);

    unsafe { let _ = net_api_buffer_free(buf); };
    Ok(())
}
