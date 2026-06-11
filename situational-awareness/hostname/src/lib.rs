// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
// Original C: derived from TrustedSec/cs-situational-awareness-bof whoami banner
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
];

// COMPUTER_NAME_FORMAT enum values
const COMPUTER_NAME_NET_BIOS: i32 = 0;
const COMPUTER_NAME_DNS_DOMAIN: i32 = 2;
const COMPUTER_NAME_DNS_FULLY_QUALIFIED: i32 = 3;

dfr_fn!(
    get_computer_name_ex_a(
        name_type: i32,
        buffer: *mut u8,
        size: *mut u32,
    ) -> i32,
    module = "kernel32.dll",
    api    = "GetComputerNameExA"
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
    print_name("NetBIOS Name", COMPUTER_NAME_NET_BIOS)?;
    print_name("DNS Domain  ", COMPUTER_NAME_DNS_DOMAIN)?;
    print_name("FQDN        ", COMPUTER_NAME_DNS_FULLY_QUALIFIED)?;
    Ok(())
}

fn print_name(label: &str, kind: i32) -> Result<(), &'static str> {
    let mut buf = [0u8; 256];
    let mut size: u32 = buf.len() as u32;
    let rc = unsafe { get_computer_name_ex_a(kind, buf.as_mut_ptr(), &mut size as *mut u32) }
        .map_err(|_| "dfr resolve failed")?;
    if rc == 0 { return Ok(()); }
    // Find NUL
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = core::str::from_utf8(&buf[..n]).unwrap_or("?");
    println!("{}: {}", label, s);
    Ok(())
}
