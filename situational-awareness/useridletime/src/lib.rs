// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! User idle time via GetLastInputInfo + GetTickCount.
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1010", name: "Application Window Discovery", tactic: "Discovery" },
];

// LASTINPUTINFO: cbSize (u32) + dwTime (u32)
#[repr(C)]
struct LastInputInfo {
    cb_size: u32,
    dw_time: u32,
}

dfr_fn!(
    get_last_input_info(plii: *mut LastInputInfo) -> i32,
    module = "user32.dll",
    api    = "GetLastInputInfo"
);

dfr_fn!(
    get_tick_count() -> u32,
    module = "kernel32.dll",
    api    = "GetTickCount"
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
    let mut lii = LastInputInfo {
        cb_size: core::mem::size_of::<LastInputInfo>() as u32,
        dw_time: 0,
    };

    let ok = unsafe { get_last_input_info(&mut lii) }
        .map_err(|_| "query failed")?;

    if ok == 0 {
        return Err("query failed");
    }

    let current_tick = unsafe { get_tick_count() }
        .map_err(|_| "tick failed")?;

    let elapsed_ms = current_tick.wrapping_sub(lii.dw_time);
    let elapsed_secs = elapsed_ms / 1000;
    let elapsed_mins = elapsed_secs / 60;
    let elapsed_hrs  = elapsed_mins / 60;

    println!("Last Input Tick  : {}", lii.dw_time);
    println!("Current Tick     : {}", current_tick);
    println!("Idle Time        : {}ms ({} sec / {} min / {} hr)",
             elapsed_ms, elapsed_secs, elapsed_mins, elapsed_hrs);

    Ok(())
}
