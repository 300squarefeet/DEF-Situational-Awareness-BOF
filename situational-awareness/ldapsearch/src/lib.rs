// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, obf_cstr};
use bof_ldap::{connect_default_dc, bind_current_user, search_paged};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1087.002", name: "Domain Account Discovery", tactic: "Discovery" },
    Technique { id: "T1018",     name: "Remote System Discovery",  tactic: "Discovery" },
];

const LDAP_PORT: u32 = 389;

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    if let Err(e) = run() {
        eprintln!("[!] {}", e);
    }
}

fn run() -> Result<(), &'static str> {
    obf_cstr! {
        let host_cstr   = c"";
        let base_cstr   = c"";
        let filter_cstr = c"(objectClass=*)";
    }

    let h = match connect_default_dc(host_cstr.as_ptr() as *const i8, LDAP_PORT) {
        Ok(h) => h,
        Err(_) => return Err("ldap query failed"),
    };
    if bind_current_user(&h).is_err() {
        return Err("ldap bind failed");
    }

    let mut attrs: [*mut i8; 0] = [];
    let mut count: u32 = 0;

    let r = search_paged(
        &h,
        base_cstr.as_ptr() as *const i8,
        filter_cstr.as_ptr() as *const i8,
        &mut attrs,
        1000,
        |e| {
            let dn = e.dn();
            if !dn.is_empty() {
                let s = core::str::from_utf8(&dn).unwrap_or("?");
                println!("{}", s);
                count += 1;
            }
        },
    );
    if r.is_err() {
        return Err("ldap query failed");
    }
    println!("[+] {} entries", count);
    Ok(())
}
