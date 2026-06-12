// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1135", name: "Network Share Discovery", tactic: "Discovery" },
];

const NERR_SUCCESS: u32 = 0;
const MAX_PREFERRED_LENGTH: u32 = 0xFFFFFFFF;

// USE_INFO_0 x64 layout:
//   ui0_local  *u16 @ offset 0   (pointer to local device name, e.g. "Z:")
//   ui0_remote *u16 @ offset 8   (pointer to remote share, e.g. "\\server\share")
//   stride = 16 bytes
const ENTRY_SIZE: usize = 16;

dfr_fn!(
    net_use_enum(
        UncServerName: *const u16,
        Level: u32,
        BufPtr: *mut *mut u8,
        PrefMaxLen: u32,
        EntriesRead: *mut u32,
        TotalEntries: *mut u32,
        ResumeHandle: *mut u32
    ) -> u32,
    module = "netapi32.dll",
    api    = "NetUseEnum"
);

dfr_fn!(
    net_api_buffer_free(Buffer: *mut core::ffi::c_void) -> u32,
    module = "netapi32.dll",
    api    = "NetApiBufferFree"
);

// ---- helpers ---------------------------------------------------------------

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

// ---- entry -----------------------------------------------------------------

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
        net_use_enum(
            core::ptr::null(),
            0,
            &mut buf_ptr,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total,
            &mut resume,
        )
    }.unwrap_or(1);
    if ret != NERR_SUCCESS {
        return Err("network connection enumeration failed");
    }

    if buf_ptr.is_null() || entries_read == 0 {
        println!("[*] No network connections found.");
        if !buf_ptr.is_null() {
            unsafe { let _ = net_api_buffer_free(buf_ptr as *mut core::ffi::c_void); };
        }
        return Ok(());
    }

    println!("Network Connections ({} total):", entries_read);
    println!("{:<20} {}", "Local", "Remote");

    for i in 0..entries_read as usize {
        let base = unsafe { buf_ptr.add(i * ENTRY_SIZE) };
        let local_ptr  = unsafe { core::ptr::read_unaligned(base as *const *const u16) };
        let remote_ptr = unsafe { core::ptr::read_unaligned(base.add(8) as *const *const u16) };

        let local  = if local_ptr.is_null()  { WStr::new() } else { wide_to_str(local_ptr, 64) };
        let remote = if remote_ptr.is_null() { WStr::new() } else { wide_to_str(remote_ptr, 256) };
        println!("{:<20} {}", local, remote);
    }

    unsafe { let _ = net_api_buffer_free(buf_ptr as *mut core::ffi::c_void); };
    Ok(())
}
