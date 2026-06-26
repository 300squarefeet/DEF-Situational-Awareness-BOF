// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1531", name: "Account Access Removal", tactic: "Impact" },
];

dfr_fn!(
    lock_work_station() -> i32,
    module = "user32.dll",
    api    = "LockWorkStation"
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
    let result = unsafe { lock_work_station() }.map_err(|_| "lock resolve")?;
    if result != 0 {
        println!("[+] workstation locked");
    } else {
        println!("[!] lock failed");
    }
    Ok(())
}
