// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Local groups via NetLocalGroupEnum (level 0).
//! Args: [hostname]
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::string::String;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1069.001", name: "Permission Groups Discovery: Local Groups", tactic: "Discovery" },
];

const MAX_PREFERRED_LENGTH: u32 = 0xFFFFFFFF;
const NERR_SUCCESS: u32 = 0;
const ERROR_MORE_DATA: u32 = 234;

// LOCALGROUP_INFO_0: *u16 name
#[repr(C)]
struct LocalGroupInfo0 { lgrpi0_name: *const u16 }

dfr_fn!(
    net_local_group_enum(
        server_name: *const u16,
        level: u32,
        buf_ptr: *mut *mut u8,
        pref_max_len: u32,
        entries_read: *mut u32,
        total_entries: *mut u32,
        resume_handle: *mut u32,
    ) -> u32,
    module = "netapi32.dll",
    api    = "NetLocalGroupEnum"
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

    let mut host_wide = [0u16; 256];
    let server_ptr: *const u16 = if host_s.is_empty() {
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
    let mut total_printed = 0u32;

    loop {
        let rc = unsafe {
            net_local_group_enum(
                server_ptr,
                0,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume,
            )
        }.map_err(|_| "query failed")?;

        if rc != NERR_SUCCESS && rc != ERROR_MORE_DATA {
            if !buf.is_null() { unsafe { let _ = net_api_buffer_free(buf); }; }
            return Err("query failed");
        }

        for i in 0..(entries_read as usize) {
            let entry = unsafe { &*(buf.add(i * core::mem::size_of::<LocalGroupInfo0>()) as *const LocalGroupInfo0) };
            let name = wide_to_str(entry.lgrpi0_name, 64);
            println!("  {}", name);
            total_printed += 1;
        }

        if !buf.is_null() { unsafe { let _ = net_api_buffer_free(buf); }; buf = core::ptr::null_mut(); }
        if rc != ERROR_MORE_DATA { break; }
    }

    println!("\n[+] {} local group(s)", total_printed);
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
