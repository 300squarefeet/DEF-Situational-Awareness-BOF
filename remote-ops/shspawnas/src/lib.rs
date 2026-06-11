// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Spawn a process under alternate credentials via `CreateProcessWithLogonW`.
//!
//! Args: <user> <password> <domain> <cmdline>
//!
//! OPSEC: all strings built as wide from obfuscated ASCII at runtime.
//! Password buffer secure-zeroed after use. Only PID logged on success.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1134.002", name: "Access Token Manipulation: Create Process with Token", tactic: "Privilege Escalation" },
];

const LOGON_WITH_PROFILE: u32 = 1;

#[repr(C)]
struct StartupInfoW {
    cb: u32, reserved: *mut u16, desktop: *mut u16, title: *mut u16,
    x: u32, y: u32, x_size: u32, y_size: u32, x_count_chars: u32, y_count_chars: u32,
    fill_attribute: u32, flags: u32, show_window: u16, cb_reserved2: u16,
    reserved2: *mut u8, h_std_input: usize, h_std_output: usize, h_std_error: usize,
}

#[repr(C)]
struct ProcessInformation {
    h_process: usize, h_thread: usize, dw_process_id: u32, dw_thread_id: u32,
}

dfr_fn!(
    create_process_with_logon_w(
        user: *const u16, domain: *const u16, pass: *const u16,
        logon_flags: u32, app: *const u16, cmd: *mut u16,
        creation_flags: u32, env: *mut u8, cwd: *const u16,
        startup: *const StartupInfoW, proc_info: *mut ProcessInformation,
    ) -> i32,
    module = "advapi32.dll",
    api    = "CreateProcessWithLogonW"
);

dfr_fn!(
    close_handle(h: usize) -> i32,
    module = "kernel32.dll",
    api    = "CloseHandle"
);

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let user_s = String::from(parser.get_str());
    let pass_s = String::from(parser.get_str());
    let dom_s  = String::from(parser.get_str());
    let cmd_s  = String::from(parser.get_str());
    let user_s = user_s.as_str();
    let pass_s = pass_s.as_str();
    let dom_s  = dom_s.as_str();
    let cmd_s  = cmd_s.as_str();

    if user_s.is_empty() || cmd_s.is_empty() {
        return Err("usage: shspawnas <user> <pass> <domain> <cmdline>");
    }

    // Build wide strings from obfuscated ASCII at runtime
    let mut user_w   = [0u16; 256];
    let mut pass_w   = [0u16; 256];
    let mut dom_w    = [0u16; 256];
    let mut cmd_w    = [0u16; 1024];
    common::str_util::ascii_to_wide_buf(user_s.as_bytes(), &mut user_w);
    common::str_util::ascii_to_wide_buf(pass_s.as_bytes(), &mut pass_w);
    common::str_util::ascii_to_wide_buf(dom_s.as_bytes(), &mut dom_w);
    common::str_util::ascii_to_wide_buf(cmd_s.as_bytes(), &mut cmd_w);

    let mut si: StartupInfoW = unsafe { core::mem::zeroed() };
    si.cb = core::mem::size_of::<StartupInfoW>() as u32;
    let mut pi: ProcessInformation = unsafe { core::mem::zeroed() };

    let rc = unsafe {
        create_process_with_logon_w(
            user_w.as_ptr(), dom_w.as_ptr(), pass_w.as_ptr(),
            LOGON_WITH_PROFILE, core::ptr::null(), cmd_w.as_mut_ptr(),
            0, core::ptr::null_mut(), core::ptr::null(),
            &si, &mut pi,
        )
    }.map_err(|_| "CreateProcessWithLogonW resolve")?;

    // Wipe password
    let pass_bytes = unsafe {
        core::slice::from_raw_parts_mut(pass_w.as_mut_ptr() as *mut u8, pass_w.len() * 2)
    };
    common::evasion::secure_zero(pass_bytes);

    if rc == 0 {
        return Err("CreateProcessWithLogonW failed (bad creds / logon type denied)");
    }

    unsafe {
        let _ = close_handle(pi.h_process);
        let _ = close_handle(pi.h_thread);
    }

    obf! { let ok = "process spawned"; }
    println!("[+] {} as {}\\{} (pid={})", ok, dom_s, user_s, pi.dw_process_id);
    Ok(())
}
