// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! NetSession enumeration via NetSessionEnum (level 10).
//! Args: <hostname>
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::string::String;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1049", name: "System Network Connections Discovery", tactic: "Discovery" },
];

const MAX_PREFERRED_LENGTH: u32 = 0xFFFFFFFF;
const NERR_SUCCESS: u32 = 0;

// SESSION_INFO_10 layout:
//   *u16 sesi10_cname  (offset 0)
//   *u16 sesi10_username (offset 8)
//   u32 sesi10_time (offset 16)
//   u32 sesi10_idle_time (offset 20)
#[repr(C)]
struct SessionInfo10 {
    cname:     *const u16,
    username:  *const u16,
    time:      u32,
    idle_time: u32,
}

dfr_fn!(
    net_session_enum(
        server_name: *const u16,
        unc_client_name: *const u16,
        user_name: *const u16,
        level: u32,
        buf_ptr: *mut *mut u8,
        pref_max_len: u32,
        entries_read: *mut u32,
        total_entries: *mut u32,
        resume_handle: *mut u32,
    ) -> u32,
    module = "netapi32.dll",
    api    = "NetSessionEnum"
);

dfr_fn!(
    net_api_buffer_free(buffer: *mut u8) -> u32,
    module = "netapi32.dll",
    api    = "NetApiBufferFree"
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
    let host_s = String::from(parser.get_str());

    // Convert hostname to wide string
    let mut host_wide = [0u16; 256];
    let server_name_ptr: *const u16 = if host_s.is_empty() {
        core::ptr::null()
    } else {
        let hlen = host_s.len().min(255);
        for (i, b) in host_s.as_bytes()[..hlen].iter().enumerate() {
            host_wide[i] = *b as u16;
        }
        host_wide.as_ptr()
    };

    let mut buf: *mut u8 = core::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume: u32 = 0;

    let rc = unsafe {
        net_session_enum(
            server_name_ptr,
            core::ptr::null(),
            core::ptr::null(),
            10,
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            &mut resume,
        )
    }.map_err(|_| "query failed")?;

    if rc != NERR_SUCCESS {
        return Err("query failed");
    }

    println!("{:<30} {:<20} {:>10} {:>10}", "Client", "User", "Time(s)", "Idle(s)");
    println!("{}", "--------------------------------------------------------------------");

    for i in 0..(entries_read as usize) {
        let entry = unsafe { &*(buf.add(i * core::mem::size_of::<SessionInfo10>()) as *const SessionInfo10) };
        let client   = wide_to_str(entry.cname,    64);
        let username = wide_to_str(entry.username, 64);
        println!("{:<30} {:<20} {:>10} {:>10}", client, username, entry.time, entry.idle_time);
    }

    println!("\n[+] {} session(s)", entries_read);
    if !buf.is_null() { unsafe { let _ = net_api_buffer_free(buf); }; }
    Ok(())
}

fn wide_to_str(ptr: *const u16, max: usize) -> WStr {
    let mut s = WStr::new();
    if ptr.is_null() { return s; }
    for i in 0..max {
        let wc = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if wc == 0 { break; }
        s.push(if wc < 128 { wc as u8 } else { b'?' });
    }
    s
}

struct WStr { buf: [u8; 64], len: usize }
impl WStr {
    fn new() -> Self { Self { buf: [0u8; 64], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for WStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
