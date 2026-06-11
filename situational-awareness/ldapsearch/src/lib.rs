// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1087.002", name: "Domain Account Discovery", tactic: "Discovery" },
    Technique { id: "T1018",     name: "Remote System Discovery",  tactic: "Discovery" },
];

const LDAP_PORT: u32 = 389;
const LDAP_SCOPE_SUBTREE: u32 = 2;
const LDAP_AUTH_NEGOTIATE: u32 = 0x0486;

dfr_fn!(
    ldap_init_a(hostname: *const i8, port_number: u32) -> *mut u8,
    module = "wldap32.dll",
    api    = "ldap_init"
);

dfr_fn!(
    ldap_bind_s_a(
        ld: *mut u8,
        dn: *const i8,
        cred: *const i8,
        method: u32,
    ) -> u32,
    module = "wldap32.dll",
    api    = "ldap_bind_s"
);

dfr_fn!(
    ldap_search_s_a(
        ld: *mut u8,
        base: *const i8,
        scope: u32,
        filter: *const i8,
        attrs: *mut *mut i8,
        attrs_only: u32,
        res: *mut *mut u8,
    ) -> u32,
    module = "wldap32.dll",
    api    = "ldap_search_s"
);

dfr_fn!(
    ldap_count_entries(ld: *mut u8, result: *mut u8) -> u32,
    module = "wldap32.dll",
    api    = "ldap_count_entries"
);

dfr_fn!(
    ldap_first_entry(ld: *mut u8, result: *mut u8) -> *mut u8,
    module = "wldap32.dll",
    api    = "ldap_first_entry"
);

dfr_fn!(
    ldap_next_entry(ld: *mut u8, entry: *mut u8) -> *mut u8,
    module = "wldap32.dll",
    api    = "ldap_next_entry"
);

dfr_fn!(
    ldap_get_dn_a(ld: *mut u8, entry: *mut u8) -> *mut i8,
    module = "wldap32.dll",
    api    = "ldap_get_dn"
);

dfr_fn!(
    ldap_unbind_s(ld: *mut u8) -> u32,
    module = "wldap32.dll",
    api    = "ldap_unbind_s"
);

dfr_fn!(
    ldap_msgfree(res: *mut u8) -> u32,
    module = "wldap32.dll",
    api    = "ldap_msgfree"
);

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // Connect to DC on localhost (beacon host context)
    let ld = unsafe { ldap_init_a(core::ptr::null(), LDAP_PORT) }
        .map_err(|_| "ldap_init resolve failed")?;
    if ld.is_null() { return Err("ldap_init failed"); }

    // SSPI negotiate bind (current user credentials)
    let rc = unsafe { ldap_bind_s_a(ld, core::ptr::null(), core::ptr::null(), LDAP_AUTH_NEGOTIATE) }
        .map_err(|_| "ldap_bind_s resolve failed")?;
    if rc != 0 {
        unsafe { let _ = ldap_unbind_s(ld); };
        return Err("ldap_bind failed");
    }

    // Default search: enumerate all user objects in base DN. Filter is
    // obfuscated and decrypted on-stack at use site.
    obf_cstr! {
        let filter_cstr = c"(&(objectClass=user)(objectCategory=person))";
    }
    let mut res: *mut u8 = core::ptr::null_mut();

    let rc2 = unsafe {
        ldap_search_s_a(
            ld,
            core::ptr::null(), // empty base = use server default
            LDAP_SCOPE_SUBTREE,
            filter_cstr.as_ptr() as *const i8,
            core::ptr::null_mut(),
            0,
            &mut res,
        )
    }.map_err(|_| "ldap_search_s resolve failed")?;

    if rc2 != 0 || res.is_null() {
        unsafe { let _ = ldap_unbind_s(ld); };
        return Err("ldap_search_s failed");
    }

    let count = unsafe { ldap_count_entries(ld, res) }.map_err(|_| "ldap_count_entries resolve")?;
    println!("LDAP USER OBJECTS ({} entries):", count);
    println!("{}", "--------------------------------------------");

    let mut entry = unsafe { ldap_first_entry(ld, res) }.map_err(|_| "ldap_first_entry resolve")?;
    while !entry.is_null() {
        let dn_ptr = unsafe { ldap_get_dn_a(ld, entry) }.map_err(|_| "ldap_get_dn resolve")?;
        if !dn_ptr.is_null() {
            let dn = cstr_to_str(dn_ptr as *const u8, 256);
            println!("DN: {}", dn);
        }
        entry = unsafe { ldap_next_entry(ld, entry) }.map_err(|_| "ldap_next_entry resolve")?;
    }

    unsafe {
        let _ = ldap_msgfree(res);
        let _ = ldap_unbind_s(ld);
    };
    Ok(())
}

fn cstr_to_str(ptr: *const u8, max: usize) -> ByteStr {
    let mut s = ByteStr::new();
    if ptr.is_null() { return s; }
    for i in 0..max {
        let b = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if b == 0 { break; }
        s.push(b);
    }
    s
}

struct ByteStr { buf: [u8; 256], len: usize }
impl ByteStr {
    fn new() -> Self { Self { buf: [0u8; 256], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for ByteStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
