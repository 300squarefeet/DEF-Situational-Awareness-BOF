// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1033", name: "System Owner/User Discovery", tactic: "Discovery" },
];

const NERR_Success: u32 = 0;
const MAX_PREFERRED_LENGTH: u32 = u32::MAX;

dfr_fn!(
    net_wksta_user_enum(
        servername: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resume_handle: *mut u32,
    ) -> u32,
    module = "netapi32.dll",
    api    = "NetWkstaUserEnum"
);

dfr_fn!(
    net_api_buffer_free(buffer: *mut u8) -> u32,
    module = "netapi32.dll",
    api    = "NetApiBufferFree"
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
    let mut buf: *mut u8 = core::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume: u32 = 0;

    // WKSTA_USER_INFO_1 layout (x64):
    // wkui1_username(*u16, +0), wkui1_logon_domain(*u16, +8),
    // wkui1_oth_domains(*u16, +16), wkui1_logon_server(*u16, +24)
    // stride = 32 bytes
    const WKSTA_USER_INFO_1_STRIDE: usize = 32;

    let rc = unsafe {
        net_wksta_user_enum(
            core::ptr::null(),
            1,
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            &mut resume,
        )
    }.map_err(|_| "resolve failed")?;

    if rc != NERR_Success {
        return Err("wksta enum failed");
    }
    if buf.is_null() {
        return Err("null buffer");
    }

    println!("LOGGED-ON USERS ({} entries):", entries_read);
    println!("{:<30} {:<20} {:<20}", "Username", "Domain", "Logon Server");
    println!("{}", "------------------------------------------------------------");

    for i in 0..entries_read as usize {
        let row   = unsafe { buf.add(i * WKSTA_USER_INFO_1_STRIDE) };
        let user  = unsafe { core::ptr::read_unaligned(row as *const *const u16) };
        let dom   = unsafe { core::ptr::read_unaligned(row.add(8) as *const *const u16) };
        let srv   = unsafe { core::ptr::read_unaligned(row.add(24) as *const *const u16) };
        println!("{:<30} {:<20} {:<20}",
            wide_to_str(user, 64), wide_to_str(dom, 64), wide_to_str(srv, 64));
    }

    unsafe { let _ = net_api_buffer_free(buf); };
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

struct WStr { buf: [u8; 128], len: usize }
impl WStr {
    fn new() -> Self { Self { buf: [0u8; 128], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for WStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
