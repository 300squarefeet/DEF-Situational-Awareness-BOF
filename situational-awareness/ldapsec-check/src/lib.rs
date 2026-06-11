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
    Technique { id: "T1518", name: "Software Discovery", tactic: "Discovery" },
];

const LDAP_PORT: u32 = 389;
const LDAP_PORT_TLS: u32 = 636;
const LDAP_AUTH_NEGOTIATE: u32 = 0x0486;
const LDAP_OPT_SIGN: u32 = 0x0095;        // LDAP_OPT_SIGN
const LDAP_OPT_ENCRYPT: u32 = 0x0096;     // LDAP_OPT_ENCRYPT
const LDAP_OPT_SERVER_CERTIFICATE: u32 = 0x0097;

dfr_fn!(
    ldap_init_a(hostname: *const i8, port: u32) -> *mut u8,
    module = "wldap32.dll",
    api    = "ldap_init"
);

dfr_fn!(
    ldap_set_option(ld: *mut u8, option: u32, invalue: *const core::ffi::c_void) -> u32,
    module = "wldap32.dll",
    api    = "ldap_set_option"
);

dfr_fn!(
    ldap_get_option(ld: *mut u8, option: u32, outvalue: *mut core::ffi::c_void) -> u32,
    module = "wldap32.dll",
    api    = "ldap_get_option"
);

dfr_fn!(
    ldap_bind_s_a(
        ld: *mut u8, dn: *const i8, cred: *const i8, method: u32,
    ) -> u32,
    module = "wldap32.dll",
    api    = "ldap_bind_s"
);

dfr_fn!(
    ldap_search_s_a(
        ld: *mut u8, base: *const i8, scope: u32,
        filter: *const i8, attrs: *mut *mut i8,
        attrs_only: u32, res: *mut *mut u8,
    ) -> u32,
    module = "wldap32.dll",
    api    = "ldap_search_s"
);

dfr_fn!(
    ldap_get_values_a(ld: *mut u8, entry: *mut u8, attr: *const i8) -> *mut *mut i8,
    module = "wldap32.dll",
    api    = "ldap_get_values"
);

dfr_fn!(
    ldap_value_free(vals: *mut *mut i8) -> u32,
    module = "wldap32.dll",
    api    = "ldap_value_free"
);

dfr_fn!(
    ldap_first_entry(ld: *mut u8, result: *mut u8) -> *mut u8,
    module = "wldap32.dll",
    api    = "ldap_first_entry"
);

dfr_fn!(
    ldap_msgfree(res: *mut u8) -> u32,
    module = "wldap32.dll",
    api    = "ldap_msgfree"
);

dfr_fn!(
    ldap_unbind(ld: *mut u8) -> u32,
    module = "wldap32.dll",
    api    = "ldap_unbind"
);

const LDAP_SCOPE_BASE: u32 = 0;
const LDAP_SUCCESS: u32 = 0;

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    println!("LDAP SECURITY CHECK:");
    println!("{}", "--------------------------------------------");

    // Check 1: Can we bind without signing?
    let ld_plain = unsafe { ldap_init_a(core::ptr::null(), LDAP_PORT) }
        .map_err(|_| "ldap_init resolve")?;
    if ld_plain.is_null() {
        return Err("ldap_init failed");
    }

    // Attempt plain (unauthenticated) simple bind
    let rc_plain = unsafe {
        ldap_bind_s_a(ld_plain, core::ptr::null(), core::ptr::null(), LDAP_AUTH_NEGOTIATE)
    }.map_err(|_| "ldap_bind_s resolve")?;

    println!("[*] Bind without signing:  {}", if rc_plain == LDAP_SUCCESS { "ALLOWED (vulnerable!)" } else { "Rejected" });

    // Check 2: Channel binding (LDAPS)
    let ld_ldaps = unsafe { ldap_init_a(core::ptr::null(), LDAP_PORT_TLS) }
        .map_err(|_| "ldap_init(tls) resolve")?;
    if !ld_ldaps.is_null() {
        let rc_ldaps = unsafe {
            ldap_bind_s_a(ld_ldaps, core::ptr::null(), core::ptr::null(), LDAP_AUTH_NEGOTIATE)
        }.map_err(|_| "ldap_bind_s(tls) resolve")?;
        println!("[*] LDAPS port 636:       {}", if rc_ldaps == LDAP_SUCCESS { "Available" } else { "Unavailable" });
        unsafe { let _ = ldap_unbind(ld_ldaps); };
    }

    // Query rootDSE ldapServiceName + rootDomainNamingContext + msDS-Behavior-Version.
    // Filter and attribute names are obfuscated and decrypted on-stack.
    let mut res: *mut u8 = core::ptr::null_mut();
    obf_cstr! {
        let filter_cstr  = c"(objectClass=*)";
        let attr_service = c"ldapServiceName";
        let attr_sasl    = c"supportedSASLMechanisms";
        let attr_naming  = c"defaultNamingContext";
        let empty_base   = c"";
    }
    let mut attrs: [*mut i8; 4] = [
        attr_service.as_ptr() as *mut i8,
        attr_sasl.as_ptr() as *mut i8,
        attr_naming.as_ptr() as *mut i8,
        core::ptr::null_mut(),
    ];

    let rc2 = unsafe {
        ldap_search_s_a(
            ld_plain, empty_base.as_ptr() as *const i8,
            LDAP_SCOPE_BASE,
            filter_cstr.as_ptr() as *const i8,
            attrs.as_mut_ptr(),
            0,
            &mut res,
        )
    }.map_err(|_| "ldap_search_s resolve")?;

    if rc2 == LDAP_SUCCESS && !res.is_null() {
        let entry = unsafe { ldap_first_entry(ld_plain, res) }.map_err(|_| "ldap_first_entry resolve")?;
        if !entry.is_null() {
            print_attr(ld_plain, entry, attr_service.as_ptr() as *const u8, attr_service.to_bytes().len());
            print_attr(ld_plain, entry, attr_naming.as_ptr() as *const u8, attr_naming.to_bytes().len());
            print_attr(ld_plain, entry, attr_sasl.as_ptr() as *const u8, attr_sasl.to_bytes().len());
        }
        unsafe { let _ = ldap_msgfree(res); };
    }

    unsafe { let _ = ldap_unbind(ld_plain); };
    Ok(())
}

fn print_attr(ld: *mut u8, entry: *mut u8, attr_ptr: *const u8, attr_len: usize) {
    let vals_result = unsafe { ldap_get_values_a(ld, entry, attr_ptr as *const i8) };
    if let Ok(vals) = vals_result {
        if !vals.is_null() {
            let attr_slice = unsafe { core::slice::from_raw_parts(attr_ptr, attr_len) };
            let name = core::str::from_utf8(attr_slice).unwrap_or("?");
            let mut i = 0usize;
            loop {
                let v = unsafe { core::ptr::read_volatile(vals.add(i)) };
                if v.is_null() { break; }
                let s = cstr_to_str(v as *const u8, 256);
                println!("[*] {}: {}", name, s);
                i += 1;
                if i > 32 { break; }
            }
            unsafe { let _ = ldap_value_free(vals); };
        }
    }
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
