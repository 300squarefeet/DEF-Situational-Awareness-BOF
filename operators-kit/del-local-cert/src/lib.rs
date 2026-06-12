// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Delete a certificate from a local Windows certificate store by SHA1 thumbprint.
//!
//! Enumerates certs in store, compares 20-byte SHA1 hash to the given hex string,
//! then calls CertDeleteCertificateFromStore on the matching context.
//!
//! Args: <store_name> <thumbprint_hex>
//!   thumbprint_hex: 40 hex characters (case-insensitive)
//!
//! MITRE ATT&CK: T1553.004 (Subvert Trust Controls: Install Root Certificate)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1553.004",
        name: "Subvert Trust Controls: Install Root Certificate",
        tactic: "Defense Evasion",
    },
];

const CERT_HASH_PROP_ID: u32 = 3;

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
    cert_delete_certificate_from_store(p_cert_context: *const u8) -> i32,
    module = "crypt32.dll",
    api    = "CertDeleteCertificateFromStore"
);

dfr_fn!(
    cert_close_store(h_cert_store: *mut u8, dw_flags: u32) -> i32,
    module = "crypt32.dll",
    api    = "CertCloseStore"
);

/// Parse a hex nibble character to its value (0–15). Returns None for invalid.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse 40-char hex string into 20-byte SHA1 array. Returns false on parse error.
fn parse_sha1_hex(hex: &str, out: &mut [u8; 20]) -> bool {
    let bytes = hex.as_bytes();
    if bytes.len() != 40 { return false; }
    for i in 0..20 {
        let hi = match hex_nibble(bytes[i * 2])     { Some(v) => v, None => return false };
        let lo = match hex_nibble(bytes[i * 2 + 1]) { Some(v) => v, None => return false };
        out[i] = (hi << 4) | lo;
    }
    true
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
    let thumbprint = String::from(parser.get_str());

    if store_name.is_empty() || thumbprint.is_empty() {
        return Err("usage: del-local-cert <store_name> <thumbprint_hex>");
    }

    let mut target_hash = [0u8; 20];
    if !parse_sha1_hex(thumbprint.as_str(), &mut target_hash) {
        return Err("thumbprint must be 40 hex chars");
    }

    let mut store_cstr = [0i8; 36];
    for (i, b) in store_name.bytes().enumerate() { if i + 1 < store_cstr.len() { store_cstr[i] = b as i8; } }

    let hstore = unsafe {
        cert_open_system_store_a(0, store_cstr.as_ptr())
    }.map_err(|_| "resolve failed")?;

    if hstore.is_null() {
        return Err("cert store open failed");
    }

    let mut found = false;
    let mut prev: *const u8 = core::ptr::null();

    loop {
        let ctx = unsafe {
            cert_enum_certificates_in_store(hstore, prev)
        }.map_err(|_| "resolve failed")?;

        if ctx.is_null() { break; }

        // Get SHA1 hash property
        let mut hash_buf = [0u8; 20];
        let mut hash_len: u32 = 20;
        let rc = unsafe {
            cert_get_certificate_context_property(
                ctx,
                CERT_HASH_PROP_ID,
                hash_buf.as_mut_ptr(),
                &mut hash_len,
            )
        }.map_err(|_| "resolve failed")?;

        if rc != 0 && hash_len == 20 && hash_buf == target_hash {
            // Found — delete it (this frees ctx, so we must not use it afterward)
            let rc_del = unsafe {
                cert_delete_certificate_from_store(ctx)
            }.map_err(|_| "resolve failed")?;

            if rc_del == 0 {
                let _ = unsafe { cert_close_store(hstore, 0) };
                return Err("cert delete failed");
            }
            found = true;
            break;
        }

        prev = ctx;
    }

    let _ = unsafe { cert_close_store(hstore, 0) };

    if !found {
        return Err("certificate not found in store");
    }

    println!("[+] certificate deleted from store: {} ({})", store_name, thumbprint);
    Ok(())
}
