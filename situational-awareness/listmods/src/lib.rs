// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! List loaded modules in the current process by walking PEB.Ldr.
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::mitre::Technique;

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1057", name: "Process Discovery", tactic: "Discovery" },
];

// PEB and LDR structures (x64 layout)
#[repr(C)]
struct PebLdrData {
    length: u32,
    initialized: u32,
    ss_handle: *mut core::ffi::c_void,
    in_load_order_module_list: ListEntry,
}

#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    _pad: u32,
    buffer: *const u16,
}

// LDR_DATA_TABLE_ENTRY (x64)
#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,           // offset 0
    in_memory_order_links: ListEntry,         // offset 16
    in_initialization_order_links: ListEntry, // offset 32
    dll_base: usize,                          // offset 48
    entry_point: usize,                       // offset 56
    size_of_image: u32,                       // offset 64
    _pad: u32,
    full_dll_name: UnicodeString,             // offset 72
    base_dll_name: UnicodeString,             // offset 88
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
    // Get PEB via GS:[0x60] on x64
    let peb_ldr: *mut PebLdrData = unsafe {
        let peb: *mut u8;
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, nomem),
        );
        let ldr_ptr = core::ptr::read_unaligned(peb.add(0x18) as *const *mut PebLdrData);
        ldr_ptr
    };

    if peb_ldr.is_null() {
        return Err("PEB walk failed");
    }

    println!("{:<64} {:>16} {:>12}", "Module", "Base", "Size");
    println!("{}", "----------------------------------------------------------------------");

    let list_head = unsafe { &(*peb_ldr).in_load_order_module_list as *const ListEntry };
    let mut cur = unsafe { (*list_head).flink };

    let mut count = 0u32;
    loop {
        if cur.is_null() || cur as *const _ == list_head { break; }
        if count > 512 { break; } // safety cap

        // LdrDataTableEntry starts at the same address as in_load_order_links
        let entry = cur as *const LdrDataTableEntry;
        let base = unsafe { (*entry).dll_base };
        let size = unsafe { (*entry).size_of_image };
        let name_us = unsafe { &(*entry).base_dll_name };

        if base != 0 {
            let name = if name_us.buffer.is_null() || name_us.length == 0 {
                WStr::from_lit(b"<unknown>")
            } else {
                wide_to_str(name_us.buffer, (name_us.length / 2) as usize)
            };
            println!("{:<64} 0x{:>014x} {:>10}", name, base, size);
        }

        cur = unsafe { (*cur).flink };
        count += 1;
    }

    println!("\n[+] {} modules listed", count);
    Ok(())
}

fn wide_to_str(ptr: *const u16, max: usize) -> WStr {
    let mut s = WStr::new();
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
    fn from_lit(b: &[u8]) -> Self {
        let mut s = Self::new();
        for &c in b { s.push(c); }
        s
    }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for WStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
