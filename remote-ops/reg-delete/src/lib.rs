// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Delete a registry key or value.
//! Args: <HIVE\path\key\[ValueName]>
//!   If path ends in a non-empty name after last \, deletes the value.
//!   Otherwise deletes the subkey.
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

const KEY_ALL_ACCESS: u32 = 0xF003F;
const ERROR_SUCCESS: u32  = 0;

dfr_fn!(
    reg_open_key_ex_a(hkey: usize, subkey: *const i8, options: u32, sam: u32, result: *mut usize) -> u32,
    module = "advapi32.dll",
    api    = "RegOpenKeyExA"
);
dfr_fn!(
    reg_delete_value_a(hkey: usize, value: *const i8) -> u32,
    module = "advapi32.dll",
    api    = "RegDeleteValueA"
);
dfr_fn!(
    reg_delete_key_a(hkey: usize, subkey: *const i8) -> u32,
    module = "advapi32.dll",
    api    = "RegDeleteKeyA"
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
    let path = String::from(parser.get_str());
    let path = path.as_str();
    if path.is_empty() {
        return Err("usage: reg-delete <HIVE\\path\\[value]>");
    }

    // Split hive from rest
    let (hive_str, rest) = path.split_once('\\').ok_or("bad path")?;
    let hroot = parse_hive(hive_str).ok_or("unknown hive")?;

    // Find last backslash to split key path from value name
    let (key_path, value_name) = match rest.rfind('\\') {
        Some(pos) => (&rest[..pos], &rest[pos+1..]),
        None => (rest, ""),
    };

    let mut key_buf = [0u8; 512];
    let mut val_buf = [0u8; 256];
    if key_path.len() >= key_buf.len() - 1 { return Err("key path too long"); }
    key_buf[..key_path.len()].copy_from_slice(key_path.as_bytes());

    if !value_name.is_empty() {
        if value_name.len() >= val_buf.len() - 1 { return Err("value name too long"); }
        val_buf[..value_name.len()].copy_from_slice(value_name.as_bytes());

        // Delete value: open parent key, delete value
        let mut hkey: usize = 0;
        let rc = unsafe {
            reg_open_key_ex_a(hroot, key_buf.as_ptr() as *const i8, 0, KEY_ALL_ACCESS, &mut hkey)
        }.map_err(|_| "open resolve")?;
        if rc != ERROR_SUCCESS { return Err("key open failed"); }

        let rc2 = unsafe {
            reg_delete_value_a(hkey, val_buf.as_ptr() as *const i8)
        }.map_err(|_| "delete value resolve")?;
        unsafe { let _ = reg_close_key(hkey); };
        if rc2 != ERROR_SUCCESS { return Err("value delete failed"); }
        obf! { let ok = "value deleted"; }
        println!("[+] {}", ok);
    } else {
        // Delete subkey: parent is everything before key_path's last segment
        let (parent_path, subkey_name) = match key_path.rfind('\\') {
            Some(pos) => (&key_path[..pos], &key_path[pos+1..]),
            None => ("", key_path),
        };

        let mut parent_buf = [0u8; 512];
        let mut sub_buf = [0u8; 256];
        if subkey_name.len() >= sub_buf.len() - 1 { return Err("subkey too long"); }
        sub_buf[..subkey_name.len()].copy_from_slice(subkey_name.as_bytes());

        let mut hkey: usize = 0;
        if parent_path.is_empty() {
            hkey = hroot;
        } else {
            if parent_path.len() >= parent_buf.len() - 1 { return Err("parent path too long"); }
            parent_buf[..parent_path.len()].copy_from_slice(parent_path.as_bytes());
            let rc = unsafe {
                reg_open_key_ex_a(hroot, parent_buf.as_ptr() as *const i8, 0, KEY_ALL_ACCESS, &mut hkey)
            }.map_err(|_| "open resolve")?;
            if rc != ERROR_SUCCESS { return Err("key open failed"); }
        }

        let rc2 = unsafe {
            reg_delete_key_a(hkey, sub_buf.as_ptr() as *const i8)
        }.map_err(|_| "delete key resolve")?;

        if hkey != hroot {
            unsafe { let _ = reg_close_key(hkey); };
        }

        if rc2 != ERROR_SUCCESS { return Err("key delete failed"); }
        obf! { let ok = "key deleted"; }
        println!("[+] {}", ok);
    }
    Ok(())
}
