// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Enumerate certificates in a local Windows certificate store.
//!
//! For each certificate, prints: subject, issuer, SHA1 thumbprint, and
//! the NotAfter expiry (as a raw FILETIME value — operators can convert offline).
//!
//! Args: <store_name>   e.g. MY | ROOT | CA
//!
//! MITRE ATT&CK: T1553 (Subvert Trust Controls)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1553",
        name: "Subvert Trust Controls",
        tactic: "Defense Evasion",
    },
];

const CERT_HASH_PROP_ID: u32           = 3;
const CERT_NAME_SIMPLE_ATTR_TYPE: u32  = 6;
const CERT_NAME_ISSUER_FLAG: u32       = 1;

dfr_fn!(
    cert_open_system_store_a(
        h_prov: usize,
        sz_subsystem_protocol: *const i8,
    ) -> *mut u8,
    module = "crypt32.dll",
    api    = "CertOpenSystemStoreA"
);

dfr_fn!(
    cert_enum_certificates_in_store(
        h_cert_store: *mut u8,
        p_prev_cert_context: *const u8,
    ) -> *const u8,
    module = "crypt32.dll",
    api    = "CertEnumCertificatesInStore"
);

dfr_fn!(
    cert_get_certificate_context_property(
        p_cert_context: *const u8,
        dw_prop_id: u32,
        pv_data: *mut u8,
        pcb_data: *mut u32,
    ) -> i32,
    module = "crypt32.dll",
    api    = "CertGetCertificateContextProperty"
);

dfr_fn!(
    cert_get_name_string_a(
        p_cert_context: *const u8,
        dw_type: u32,
        dw_flags: u32,
        pv_type_para: *const u8,
        psz_name_string: *mut u8,
        cch_name_string: u32,
    ) -> u32,
    module = "crypt32.dll",
    api    = "CertGetNameStringA"
);

dfr_fn!(
    cert_close_store(h_cert_store: *mut u8, dw_flags: u32) -> i32,
    module = "crypt32.dll",
    api    = "CertCloseStore"
);

/// Format 20-byte SHA1 hash as lowercase hex into a fixed buffer.
fn fmt_sha1_hex(hash: &[u8; 20], out: &mut [u8; 41]) {
    const HEX: &[u8] = b"0123456789abcdef";
    for i in 0..20 {
        out[i * 2]     = HEX[(hash[i] >> 4) as usize];
        out[i * 2 + 1] = HEX[(hash[i] & 0xf) as usize];
    }
    out[40] = 0;
}

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
    let store_name = String::from(parser.get_str());
    if store_name.is_empty() {
        return Err("usage: enum-local-cert <store_name>");
    }

    let mut store_cstr = [0i8; 36];
    for (i, b) in store_name.bytes().enumerate() { if i + 1 < store_cstr.len() { store_cstr[i] = b as i8; } }

    let hstore = unsafe {
        cert_open_system_store_a(0, store_cstr.as_ptr())
    }.map_err(|_| "resolve failed")?;

    if hstore.is_null() {
        return Err("cert store open failed");
    }

    println!("CERTIFICATES in store: {}", store_name);
    println!("{}", "--------------------------------------------");

    let mut count: u32 = 0;
    let mut prev: *const u8 = core::ptr::null();

    loop {
        let ctx = unsafe {
            cert_enum_certificates_in_store(hstore, prev)
        }.map_err(|_| "resolve failed")?;

        if ctx.is_null() { break; }
        count += 1;

        // Subject name
        let mut subj_buf = [0u8; 256];
        let _ = unsafe {
            cert_get_name_string_a(
                ctx,
                CERT_NAME_SIMPLE_ATTR_TYPE,
                0,
                core::ptr::null(),
                subj_buf.as_mut_ptr(),
                subj_buf.len() as u32,
            )
        };
        let subj = cstr_to_str(subj_buf.as_ptr(), subj_buf.len());

        // Issuer name
        let mut issu_buf = [0u8; 256];
        let _ = unsafe {
            cert_get_name_string_a(
                ctx,
                CERT_NAME_SIMPLE_ATTR_TYPE,
                CERT_NAME_ISSUER_FLAG,
                core::ptr::null(),
                issu_buf.as_mut_ptr(),
                issu_buf.len() as u32,
            )
        };
        let issu = cstr_to_str(issu_buf.as_ptr(), issu_buf.len());

        // SHA1 thumbprint
        let mut hash_buf = [0u8; 20];
        let mut hash_len: u32 = 20;
        let _ = unsafe {
            cert_get_certificate_context_property(
                ctx,
                CERT_HASH_PROP_ID,
                hash_buf.as_mut_ptr(),
                &mut hash_len,
            )
        };
        let mut hex_buf = [0u8; 41];
        fmt_sha1_hex(&hash_buf, &mut hex_buf);
        let thumb = cstr_to_str(hex_buf.as_ptr(), 40);

        // NotAfter: pCertContext→pCertInfo→NotAfter
        // Layout: pCertContext[24] = *pCertInfo (ptr), pCertInfo[32] = NotAfter (FILETIME=u64)
        let not_after_ft = unsafe {
            let cert_info_ptr = core::ptr::read_unaligned(ctx.add(24) as *const usize);
            if cert_info_ptr != 0 {
                core::ptr::read_unaligned((cert_info_ptr + 32) as *const u64)
            } else {
                0u64
            }
        };

        println!("  [{}]", count);
        println!("    Subject : {}", subj);
        println!("    Issuer  : {}", issu);
        println!("    Thumb   : {}", thumb);
        println!("    Expiry  : FILETIME={:#018x}", not_after_ft);

        prev = ctx;
    }

    let _ = unsafe { cert_close_store(hstore, 0) };
    println!("{}", "--------------------------------------------");
    println!("[*] total: {} certificates", count);
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
