// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1018", name: "Remote System Discovery", tactic: "Discovery" },
];

dfr_fn!(
    net_server_enum(
        servername: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        servertype: u32,
        domain: *const u16,
        resume_handle: *mut u32,
    ) -> u32,
    module = "netapi32.dll",
    api    = "NetServerEnum"
);

dfr_fn!(
    net_api_buffer_free(buffer: *mut core::ffi::c_void) -> u32,
    module = "netapi32.dll",
    api    = "NetApiBufferFree"
);

struct WStr { buf: [u8; 256], len: usize }
impl WStr {
    fn new() -> Self { Self { buf: [0u8; 256], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for WStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
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

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    let mut buf_ptr: *mut u8 = core::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total: u32 = 0;
    let mut resume: u32 = 0;

    let ret = unsafe {
        net_server_enum(
            core::ptr::null(), 100, &mut buf_ptr, 0xFFFFFFFFu32,
            &mut entries_read, &mut total, 0xFFFFFFFFu32,
            core::ptr::null(), &mut resume,
        )
    }.unwrap_or(1);

    if ret != 0 {
        return Err("enum failed");
    }

    if buf_ptr.is_null() {
        return Err("enum failed");
    }

    println!("Network Servers ({} found, {} total):", entries_read, total);

    // SERVER_INFO_100 on x64: sv100_platform_id(u32 @ 0), [4 bytes pad], sv100_name(*u16 @ 8)
    // Stride = 16 bytes
    const ENTRY_SIZE: usize = 16;
    for i in 0..entries_read as usize {
        let base = unsafe { buf_ptr.add(i * ENTRY_SIZE) };
        let name_ptr = unsafe { core::ptr::read_unaligned(base.add(8) as *const *const u16) };
        if !name_ptr.is_null() {
            let name = wide_to_str(name_ptr, 64);
            println!("  \\\\{}", name);
        }
    }

    unsafe { let _ = net_api_buffer_free(buf_ptr as *mut core::ffi::c_void); };
    Ok(())
}
