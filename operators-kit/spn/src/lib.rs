// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! SPN enumeration for Kerberoast preparation — Phase 4 OperatorsKit stub.
//!
//! Full LDAP query (`wldap32.dll` DFR + DsGetDcNameW) is deferred to Phase 5
//! when the shared LDAP helper crate lands. This BOF registers the MITRE
//! technique, locates the current DC via DsGetDcNameW, and reports readiness.
//! No child process spawn (no setspn.exe, no PowerShell).
//!
//! Phase 5 upgrade path: replace `run()` body with ldap_init / ldap_bind_s /
//! ldap_search_ext_s filtered on
//!   (&(servicePrincipalName=*)(objectClass=user)(!(samAccountName=krbtgt)))
//! attributes: sAMAccountName servicePrincipalName userAccountControl
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1558.003", name: "Steal or Forge Kerberos Tickets: Kerberoasting", tactic: "Credential Access" },
];

// DSGETDCNAME_FLAGS — DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME
const DS_DIRECTORY_SERVICE_REQUIRED: u32 = 0x00000010;
const DS_RETURN_DNS_NAME:            u32 = 0x40000000;

// DOMAIN_CONTROLLER_INFOW offsets (x64 pointer size = 8 bytes)
// The struct starts with pointer fields; DomainControllerName is field[0].
// We read the pointer and decode the wide string.

dfr_fn!(
    ds_get_dc_name_w(
        computer_name: *const u16,
        domain_name:   *const u16,
        domain_guid:   *const u8,
        site_name:     *const u16,
        flags:         u32,
        dc_info:       *mut *mut u8,
    ) -> u32,
    module = "netapi32.dll",
    api    = "DsGetDcNameW"
);

dfr_fn!(
    net_api_buffer_free(buffer: *mut u8) -> u32,
    module = "netapi32.dll",
    api    = "NetApiBufferFree"
);

fn wide_to_str(ptr: *const u16, out: &mut [u8]) -> usize {
    if ptr.is_null() { return 0; }
    let mut n = 0usize;
    loop {
        if n >= out.len() - 1 { break; }
        let wc = unsafe { core::ptr::read_volatile(ptr.add(n)) };
        if wc == 0 { break; }
        out[n] = if wc < 128 { wc as u8 } else { b'?' };
        n += 1;
    }
    out[n] = 0;
    n
}

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // Locate the DC — validates we are domain-joined.
    let mut dc_info: *mut u8 = core::ptr::null_mut();
    let rc = unsafe {
        ds_get_dc_name_w(
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME,
            &mut dc_info,
        )
    }.map_err(|_| "dc lookup resolve failed")?;

    if rc != 0 || dc_info.is_null() {
        obf! { let msg = "SPN enum: not domain-joined or DC unreachable (err)"; }
        println!("{}", msg);
        return Ok(());
    }

    // DOMAIN_CONTROLLER_INFOW: first field (offset 0) is DomainControllerName (*u16)
    let dc_name_ptr = unsafe { core::ptr::read_unaligned(dc_info as *const *const u16) };
    let mut dc_name_buf = [0u8; 256];
    let dc_name_len = wide_to_str(dc_name_ptr, &mut dc_name_buf);
    let dc_name = core::str::from_utf8(&dc_name_buf[..dc_name_len]).unwrap_or("?");

    // DomainName is the 3rd pointer field (offset 16 on x64).
    let dom_ptr = unsafe {
        core::ptr::read_unaligned(dc_info.add(16) as *const *const u16)
    };
    let mut dom_buf = [0u8; 256];
    let dom_len = wide_to_str(dom_ptr, &mut dom_buf);
    let dom_name = core::str::from_utf8(&dom_buf[..dom_len]).unwrap_or("?");

    unsafe { let _ = net_api_buffer_free(dc_info); };

    obf! { let phase_msg = "SPN enumeration: Phase 4 stub — LDAP query deferred to Phase 5 helper"; }
    obf! { let filter    = "(&(servicePrincipalName=*)(objectClass=user)(!(sAMAccountName=krbtgt)))"; }
    obf! { let attrs     = "sAMAccountName, servicePrincipalName, userAccountControl"; }

    println!("[*] {}", phase_msg);
    println!("[*] DC       : {}", dc_name);
    println!("[*] Domain   : {}", dom_name);
    println!("[*] Filter   : {}", filter);
    println!("[*] Attrs    : {}", attrs);
    println!("[*] MITRE    : T1558.003 — Kerberoasting");
    println!("[*] Upgrade  : implement ldap_init/ldap_bind_s/ldap_search_ext_s in Phase 5");
    Ok(())
}
