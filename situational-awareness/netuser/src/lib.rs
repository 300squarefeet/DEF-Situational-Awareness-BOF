// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1087.001", name: "Local Account Discovery",  tactic: "Discovery" },
    Technique { id: "T1087.002", name: "Domain Account Discovery", tactic: "Discovery" },
];

const NERR_Success: u32 = 0;
const MAX_PREFERRED_LENGTH: u32 = u32::MAX;
const UF_ACCOUNTDISABLE: u32 = 0x0002;

dfr_fn!(
    net_user_enum(
        servername: *const u16,
        level: u32,
        filter: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resume_handle: *mut u32,
    ) -> u32,
    module = "netapi32.dll",
    api    = "NetUserEnum"
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

    // Level 1 = USER_INFO_1: usri1_name(*u16), usri1_password(*u16),
    //   usri1_password_age(u32), usri1_priv(u32), usri1_home_dir(*u16),
    //   usri1_comment(*u16), usri1_flags(u32), usri1_script_path(*u16)
    // Each pointer is 8 bytes on x64 → row stride = 8*5 + 4*2 = 48 bytes? Actually:
    // name(8)+pass(8)+age(4)+[pad4]+priv(4)+[pad4]+home(8)+comment(8)+flags(4)+[pad4]+script(8)
    // = 8+8+4+4+4+4+8+8+4+4+8 = 64 bytes
    const USER_INFO_1_STRIDE: usize = 64;

    let rc = unsafe {
        net_user_enum(
            core::ptr::null(),  // local machine
            1,
            0, // FILTER_NORMAL_ACCOUNT (0) — pass 0 for all
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            &mut resume,
        )
    }.map_err(|_| "resolve failed")?;

    if rc != NERR_Success {
        return Err("user enum failed");
    }
    if buf.is_null() {
        return Err("null buffer");
    }

    println!("LOCAL USERS ({} entries):", entries_read);
    println!("{:<24} {:<10} {:<10}", "Username", "Priv", "Status");
    println!("{}", "--------------------------------------------");

    for i in 0..entries_read as usize {
        let row = unsafe { buf.add(i * USER_INFO_1_STRIDE) };
        let name_ptr = unsafe { core::ptr::read_unaligned(row as *const *const u16) };
        let priv_val = unsafe { core::ptr::read_unaligned(row.add(20) as *const u32) };
        let flags    = unsafe { core::ptr::read_unaligned(row.add(52) as *const u32) };

        let name = wide_to_str(name_ptr, 64);
        let priv_s = match priv_val { 0 => "Guest", 1 => "User", 2 => "Admin", _ => "?" };
        let status = if flags & UF_ACCOUNTDISABLE != 0 { "Disabled" } else { "Enabled" };
        println!("{:<24} {:<10} {:<10}", name, priv_s, status);
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
