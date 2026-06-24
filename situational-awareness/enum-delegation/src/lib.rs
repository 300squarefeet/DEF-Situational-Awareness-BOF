// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//! enum-delegation — Kerberos constrained/unconstrained delegation enumeration.
//! MITRE ATT&CK: T1134.001
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::mitre::Technique;
use common::obf_cstr;
use bof_ldap::{connect_default_dc, bind_current_user, search_paged};

const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1134.001",
    name: "Token Impersonation/Theft",
    tactic: "Privilege Escalation",
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
        let attr_deleg = c"msDS-AllowedToDelegateTo";
        let attr_dns  = c"dNSHostName";
        let filter_constrained = c"(msDS-AllowedToDelegateTo=*)";
        let filter_unconstrained = c"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))";
    }

    let h = connect_default_dc(host_cstr.as_ptr() as *const i8, LDAP_PORT)
        .map_err(|_| "ldap connect failed")?;
    if bind_current_user(&h).is_err() {
        return Err("ldap bind failed");
    }

    // --- Constrained delegation ---
    println!("CONSTRAINED DELEGATION:");

    let mut attrs_c: [*mut i8; 3] = [
        attr_sam.as_ptr() as *mut i8,
        attr_deleg.as_ptr() as *mut i8,
        core::ptr::null_mut(),
    ];
    let mut c_count: u32 = 0;
    let _ = search_paged(
        &h, base_cstr.as_ptr() as *const i8,
        filter_constrained.as_ptr() as *const i8,
        &mut attrs_c, 1000,
        |e| {
            let sams = e.values(attr_sam.as_ptr() as *const i8);
            let delegs = e.values(attr_deleg.as_ptr() as *const i8);
            if let Some(sam) = sams.first() {
                let s = core::str::from_utf8(sam).unwrap_or("?");
                println!("  {}", s);
                for d in &delegs {
                    let ds = core::str::from_utf8(d).unwrap_or("?");
                    println!("    -> {}", ds);
                }
                c_count += 1;
            }
        },
    );
    println!("[+] {} constrained accounts", c_count);

    // --- Unconstrained delegation ---
    println!("UNCONSTRAINED DELEGATION:");

    let mut attrs_u: [*mut i8; 3] = [
        attr_sam.as_ptr() as *mut i8,
        attr_dns.as_ptr() as *mut i8,
        core::ptr::null_mut(),
    ];
    let mut u_count: u32 = 0;
    let _ = search_paged(
        &h, base_cstr.as_ptr() as *const i8,
        filter_unconstrained.as_ptr() as *const i8,
        &mut attrs_u, 1000,
        |e| {
            let sams = e.values(attr_sam.as_ptr() as *const i8);
            let dns = e.values(attr_dns.as_ptr() as *const i8);
            if let Some(sam) = sams.first() {
                let s = core::str::from_utf8(sam).unwrap_or("?");
                let d = dns.first().map(|v| core::str::from_utf8(v).unwrap_or("?")).unwrap_or("");
                println!("  {} ({})", s, d);
                u_count += 1;
            }
        },
    );
    println!("[+] {} unconstrained computers", u_count);
    Ok(())
}
