// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//! asreproast — AS-REP roastable account enumeration via LDAP.
//! MITRE ATT&CK: T1558.004
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::mitre::Technique;
use common::obf_cstr;
use bof_ldap::{connect_default_dc, bind_current_user, search_paged};

const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1558.004",
    name: "AS-REP Roasting",
    tactic: "Credential Access",
}];

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
        let host_cstr = c"";
        let base_cstr = c"";
        let attr_sam  = c"sAMAccountName";
        let attr_uac  = c"userAccountControl";
    }

    let h = connect_default_dc(host_cstr.as_ptr() as *const i8, LDAP_PORT)
        .map_err(|_| "ldap connect failed")?;
    if bind_current_user(&h).is_err() {
        return Err("ldap bind failed");
    }

    obf_cstr! {
        let filter_cstr = c"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
    }

    let mut attrs: [*mut i8; 3] = [
        attr_sam.as_ptr() as *mut i8,
        attr_uac.as_ptr() as *mut i8,
        core::ptr::null_mut(),
    ];

    let mut count: u32 = 0;
    let r = search_paged(
        &h,
        base_cstr.as_ptr() as *const i8,
        filter_cstr.as_ptr() as *const i8,
        &mut attrs,
        1000,
        |e| {
            let sams = e.values(attr_sam.as_ptr() as *const i8);
            if !sams.is_empty() {
                let s = core::str::from_utf8(&sams[0]).unwrap_or("?");
                println!("  {}", s);
                count += 1;
            }
        },
    );
    if r.is_err() {
        return Err("ldap query failed");
    }
    println!("[+] {} accounts without preauth", count);
    Ok(())
}
