// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
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
    // Zero-API: walk PEB->ProcessParameters->Environment
    // PEB offset on x64: gs:[0x60]
    // PEB+0x20 = ProcessParameters (RTL_USER_PROCESS_PARAMETERS*)
    // RTL_USER_PROCESS_PARAMETERS+0x80 = Environment (*mut u16)
    // RTL_USER_PROCESS_PARAMETERS+0x03F0 = EnvironmentSize (SIZE_T)
    let env_ptr: *const u16 = unsafe {
        let peb: *const u8;
        core::arch::asm!(
            "mov {peb}, gs:[0x60]",
            peb = out(reg) peb,
        );
        if peb.is_null() { return Err("PEB null"); }
        let params = core::ptr::read_unaligned(peb.add(0x20) as *const *const u8);
        if params.is_null() { return Err("ProcessParameters null"); }
        core::ptr::read_unaligned(params.add(0x80) as *const *const u16)
    };

    if env_ptr.is_null() {
        return Err("Environment null");
    }

    println!("ENVIRONMENT:");
    println!("{}", "----------------------------------------");

    // Environment block is a sequence of wide-char NUL-terminated strings,
    // terminated by an empty string (double NUL).
    let mut offset: usize = 0;
    loop {
        let start = unsafe { env_ptr.add(offset) };
        // Find end of this entry
        let mut len = 0usize;
        loop {
            let wc = unsafe { core::ptr::read_volatile(start.add(len)) };
            if wc == 0 { break; }
            len += 1;
            if len > 32767 { break; } // safety cap
        }
        if len == 0 { break; } // double NUL = end of block

        // Convert wide to ASCII (printable range only)
        let mut line = [0u8; 512];
        let copy_len = len.min(line.len() - 1);
        for i in 0..copy_len {
            let wc = unsafe { core::ptr::read_volatile(start.add(i)) };
            line[i] = if wc < 128 { wc as u8 } else { b'?' };
        }
        let s = core::str::from_utf8(&line[..copy_len]).unwrap_or("?");
        println!("{}", s);

        offset += len + 1;
    }
    Ok(())
}
