// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Set a registry value.
//! Args: <HIVE\path\key> <value_name> <type> <data>
//! type: REG_SZ, REG_DWORD, REG_BINARY
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1112", name: "Modify Registry", tactic: "Defense Evasion" },
];

const HKEY_CURRENT_USER:  usize = 0x80000001;
const HKEY_LOCAL_MACHINE: usize = 0x80000002;
const HKEY_USERS:         usize = 0x80000003;
const HKEY_CURRENT_CONFIG: usize = 0x80000005;

const REG_SZ:     u32 = 1;
const REG_BINARY: u32 = 3;
const REG_DWORD:  u32 = 4;

const REG_OPTION_NON_VOLATILE: u32 = 0;
const KEY_WRITE: u32 = 0x20006;
const ERROR_SUCCESS: u32 = 0;

dfr_fn!(
    reg_create_key_ex_a(
        hkey: usize, subkey: *const i8, reserved: u32, class_: *const i8,
        options: u32, sam: u32, sec: *mut u8,
        result: *mut usize, disposition: *mut u32,
    ) -> i32,
    module = "advapi32.dll",
    api    = "RegCreateKeyExA"
);
dfr_fn!(
    reg_set_value_ex_a(
        hkey: usize, name: *const i8, reserved: u32,
        ty: u32, data: *const u8, cb: u32,
    ) -> i32,
    module = "advapi32.dll",
    api    = "RegSetValueExA"
);
dfr_fn!(
    reg_close_key(hkey: usize) -> u32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
);

fn parse_hive(s: &str) -> Option<usize> {
    if s.eq_ignore_ascii_case("HKLM") { return Some(HKEY_LOCAL_MACHINE); }
    if s.eq_ignore_ascii_case("HKCU") { return Some(HKEY_CURRENT_USER); }
    if s.eq_ignore_ascii_case("HKU")  { return Some(HKEY_USERS); }
    if s.eq_ignore_ascii_case("HKCC") { return Some(HKEY_CURRENT_CONFIG); }
    None
}

fn parse_u32_flex(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let mut v: u32 = 0;
        for b in hex.bytes() {
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'a'..=b'f' => (b - b'a' + 10) as u32,
                b'A'..=b'F' => (b - b'A' + 10) as u32,
                _ => return None,
            };
            v = v.checked_mul(16)?.checked_add(digit)?;
        }
        return Some(v);
    }
    let mut v: u32 = 0;
    let mut any = false;
    for b in s.bytes() {
        if !b.is_ascii_digit() { return None; }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u32)?;
        any = true;
    }
    if any { Some(v) } else { None }
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
    let key_path  = String::from(parser.get_str());
    let val_name  = String::from(parser.get_str());
    let type_str  = String::from(parser.get_str());
    let data_str  = String::from(parser.get_str());
    let key_path  = key_path.as_str();
    let val_name  = val_name.as_str();
    let type_str  = type_str.as_str();
    let data_str  = data_str.as_str();

    if key_path.is_empty() || val_name.is_empty() || type_str.is_empty() || data_str.is_empty() {
        return Err("usage: reg-set <HIVE\\key> <value> <REG_SZ|REG_DWORD|REG_BINARY> <data>");
    }

    let (hive_str, subkey) = key_path.split_once('\\').ok_or("bad key path")?;
    let hroot = parse_hive(hive_str).ok_or("unknown hive")?;

    let reg_type = if type_str.eq_ignore_ascii_case("REG_SZ")     { REG_SZ }
                   else if type_str.eq_ignore_ascii_case("REG_DWORD") { REG_DWORD }
                   else if type_str.eq_ignore_ascii_case("REG_BINARY") { REG_BINARY }
                   else { return Err("unknown type"); };

    let mut key_buf = [0u8; 512];
    let mut vn_buf  = [0u8; 256];
    if subkey.len() >= key_buf.len() - 1 { return Err("key too long"); }
    if val_name.len() >= vn_buf.len() - 1 { return Err("value name too long"); }
    key_buf[..subkey.len()].copy_from_slice(subkey.as_bytes());
    vn_buf[..val_name.len()].copy_from_slice(val_name.as_bytes());

    let mut hkey: usize = 0;
    let mut disp: u32 = 0;
    let rc = unsafe {
        reg_create_key_ex_a(
            hroot, key_buf.as_ptr() as *const i8,
            0, core::ptr::null(), REG_OPTION_NON_VOLATILE, KEY_WRITE,
            core::ptr::null_mut(), &mut hkey, &mut disp,
        )
    }.map_err(|_| "create key resolve")?;
    if rc != ERROR_SUCCESS as i32 || hkey == 0 {
        return Err("key create/open failed");
    }

    let rc2 = match reg_type {
        REG_DWORD => {
            let dw = parse_u32_flex(data_str).ok_or("invalid DWORD")?;
            let dw_bytes = dw.to_le_bytes();
            unsafe {
                reg_set_value_ex_a(
                    hkey, vn_buf.as_ptr() as *const i8, 0,
                    REG_DWORD, dw_bytes.as_ptr(), 4,
                )
            }.map_err(|_| "set value resolve")?
        }
        REG_SZ => {
            let mut data_buf = [0u8; 1024];
            let len = data_str.len();
            if len >= data_buf.len() - 1 { unsafe { let _ = reg_close_key(hkey); }; return Err("data too long"); }
            data_buf[..len].copy_from_slice(data_str.as_bytes());
            unsafe {
                reg_set_value_ex_a(
                    hkey, vn_buf.as_ptr() as *const i8, 0,
                    REG_SZ, data_buf.as_ptr(), (len + 1) as u32,
                )
            }.map_err(|_| "set value resolve")?
        }
        _ => {
            // REG_BINARY: hex string e.g. "deadbeef"
            let mut bin_buf = [0u8; 512];
            let hex = data_str.as_bytes();
            if hex.len() % 2 != 0 { unsafe { let _ = reg_close_key(hkey); }; return Err("odd hex"); }
            let n = hex.len() / 2;
            if n > bin_buf.len() { unsafe { let _ = reg_close_key(hkey); }; return Err("data too long"); }
            for i in 0..n {
                let hi = hex_nibble(hex[i*2]).ok_or("bad hex")?;
                let lo = hex_nibble(hex[i*2+1]).ok_or("bad hex")?;
                bin_buf[i] = (hi << 4) | lo;
            }
            unsafe {
                reg_set_value_ex_a(
                    hkey, vn_buf.as_ptr() as *const i8, 0,
                    REG_BINARY, bin_buf.as_ptr(), n as u32,
                )
            }.map_err(|_| "set value resolve")?
        }
    };

    unsafe { let _ = reg_close_key(hkey); };
    if rc2 != ERROR_SUCCESS as i32 { return Err("set value failed"); }
    obf! { let ok = "value set"; }
    println!("[+] {}", ok);
    Ok(())
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
