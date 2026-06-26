// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
];

dfr_fn!(
    get_tick_count64() -> u64,
    module = "kernel32.dll",
    api    = "GetTickCount64"
);

// ---- entry -----------------------------------------------------------------

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    let ms = unsafe { get_tick_count64() }.unwrap_or(0);
    let total_secs = ms / 1000;
    let days  = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let mins  = (total_secs % 3600) / 60;
    let secs  = total_secs % 60;
    println!("Uptime: {} days, {:02}:{:02}:{:02}", days, hours, mins, secs);
    Ok(())
}
