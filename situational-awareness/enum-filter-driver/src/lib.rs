// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
#![no_std]
#![cfg_attr(not(test), no_main)]


use alloc::vec::Vec;

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1518.001", name: "Security Software Discovery", tactic: "Discovery" },
    Technique { id: "T1014",     name: "Rootkit",                     tactic: "Defense Evasion" },
];

const ERROR_SUCCESS: u32 = 0;
const ERROR_NO_MORE_ITEMS: u32 = 259;

// FILTER_FULL_INFORMATION: FilterNameLength u16, FilterNameBufferOffset u32, FilterNameBuffer[]
// FilterFindFirst/Next use FltmgrInfo = 0x20 for full info

dfr_fn!(
    filter_find_first(
        information_class: u32,
        buffer: *mut u8,
        buffer_size: u32,
        bytes_returned: *mut u32,
        filter_find: *mut usize,
    ) -> u32,
    module = "fltlib.dll",
    api    = "FilterFindFirst"
);

dfr_fn!(
    filter_find_next(
        filter_find: usize,
        information_class: u32,
        buffer: *mut u8,
        buffer_size: u32,
        bytes_returned: *mut u32,
    ) -> u32,
    module = "fltlib.dll",
    api    = "FilterFindNext"
);

dfr_fn!(
    filter_find_close(filter_find: usize) -> u32,
    module = "fltlib.dll",
    api    = "FilterFindClose"
);

// FilterFullInformation = 1
const FILTER_FULL_INFORMATION: u32 = 1;

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    let mut buf: Vec<u8> = alloc::vec![0u8; 4096];
    let mut bytes_returned: u32 = 0;
    let mut handle: usize = 0;

    let rc = unsafe {
        filter_find_first(
            FILTER_FULL_INFORMATION,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut bytes_returned,
            &mut handle,
        )
    }.map_err(|_| "FilterFindFirst resolve failed")?;

    if rc != ERROR_SUCCESS {
        // fltlib might not be present on all systems
        println!("[!] FilterFindFirst returned 0x{:x} (no filters or access denied)", rc);
        return Ok(());
    }

    println!("MINIFILTER DRIVERS:");
    println!("{}", "--------------------------------------------");

    loop {
        // Parse FILTER_FULL_INFORMATION:
        // +0  NextEntryOffset u32
        // +4  FrameID u32
        // +8  NumberOfInstances u32
        // +12 FilterNameLength u16
        // +14 (pad 2)
        // +16 FilterNameBuffer [u16; var]
        let ptr = buf.as_ptr();
        let _next = unsafe { core::ptr::read_unaligned(ptr as *const u32) };
        let num_instances = unsafe { core::ptr::read_unaligned(ptr.add(8) as *const u32) };
        let name_len_bytes = unsafe { core::ptr::read_unaligned(ptr.add(12) as *const u16) } as usize;
        let name_ptr = unsafe { ptr.add(16) as *const u16 };
        let name_chars = name_len_bytes / 2;

        let name = wide_to_str(name_ptr, name_chars);
        println!("  {} (instances: {})", name, num_instances);

        // Try next
        bytes_returned = 0;
        for b in buf.iter_mut() { *b = 0; }
        let rc2 = unsafe {
            filter_find_next(
                handle,
                FILTER_FULL_INFORMATION,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut bytes_returned,
            )
        }.map_err(|_| "FilterFindNext resolve failed")?;

        if rc2 == ERROR_NO_MORE_ITEMS { break; }
        if rc2 != ERROR_SUCCESS { break; }
    }

    unsafe { let _ = filter_find_close(handle); };
    Ok(())
}

fn wide_to_str(ptr: *const u16, max: usize) -> WStr {
    let mut s = WStr::new();
    if ptr.is_null() { return s; }
    for i in 0..max.min(64) {
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
