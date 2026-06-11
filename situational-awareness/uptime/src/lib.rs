// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
// Original C: TrustedSec/cs-situational-awareness-bof — uptime.c
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::mitre::Technique;

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
];

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // KUSER_SHARED_DATA at fixed VA 0x7FFE0000.
    // SystemTime: 100-ns intervals since 1601-01-01 UTC, at offset 0x14.
    // InterruptTime: same units since boot, at offset 0x08.
    const KUSD: usize = 0x7FFE0000;
    let interrupt_time_100ns = unsafe { read_u64(KUSD + 0x08) };
    let system_time_100ns    = unsafe { read_u64(KUSD + 0x14) };

    let uptime_secs = interrupt_time_100ns / 10_000_000;
    let days   = uptime_secs / 86400;
    let hours  = (uptime_secs % 86400) / 3600;
    let mins   = (uptime_secs % 3600) / 60;
    let secs   = uptime_secs % 60;

    println!("UPTIME:      {}d {}h {}m {}s", days, hours, mins, secs);
    println!("SYSTEM_TIME: {} (FILETIME 100ns since 1601)", system_time_100ns);
    Ok(())
}

#[inline(always)]
unsafe fn read_u64(addr: usize) -> u64 {
    core::ptr::read_volatile(addr as *const u64)
}
