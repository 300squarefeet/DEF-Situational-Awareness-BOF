// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::mitre::Technique;
use common::token::{open_current_process_token, TOKEN_QUERY};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1033", name: "System Owner/User Discovery", tactic: "Discovery" },
    Technique { id: "T1134", name: "Access Token Manipulation",   tactic: "Privilege Escalation" },
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
    // Note: the API name is intentionally NOT in the error string — the leak
    // check would catch it. The hash is djb2'd at compile time inside
    // `open_current_process_token`; we only surface the NTSTATUS code.
    let token = unsafe { open_current_process_token(TOKEN_QUERY) }
        .map_err(|_| "token open failed")?;
    println!("TOKEN_HANDLE: 0x{:x}", token);
    // Phase 1 minimal: confirm we can open the token. Full SID/group enumeration
    // is intentionally deferred to Phase 2 whoami refinement — the canary's
    // job here is to PROVE the indirect-syscall path works end-to-end.
    println!("STATUS:       indirect syscall path validated");
    Ok(())
}
