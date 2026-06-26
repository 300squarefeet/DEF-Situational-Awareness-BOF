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
    Technique { id: "T1016.001", name: "Internet Connection Discovery", tactic: "Discovery" },
];

// DNS_STATUS = LONG (i32), DNS_CACHE_ENTRY layout:
// pNext: *mut DNS_CACHE_ENTRY (+0)
// pszName: *const i8 (+8)
// wType: u16 (+16)
// wDataLength: u16 (+18)
// dwFlags: u32 (+20)

dfr_fn!(
    dns_get_cache_data_table(
        entry_list: *mut *mut u8,
    ) -> i32,
    module = "dnsapi.dll",
    api    = "DnsGetCacheDataTable"
);

dfr_fn!(
    dns_record_list_free(record_list: *mut u8, free_type: u32) -> (),
    module = "dnsapi.dll",
    api    = "DnsRecordListFree"
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
    let mut entry_list: *mut u8 = core::ptr::null_mut();
    let rc = unsafe { dns_get_cache_data_table(&mut entry_list) }
        .map_err(|_| "DnsGetCacheDataTable resolve failed")?;

    if rc != 0 {
        return Err("DnsGetCacheDataTable failed");
    }

    println!("DNS CACHE:");
    println!("{:<50} {:<8}", "Name", "Type");
    println!("{}", "------------------------------------------------------------");

    let mut entry = entry_list;
    while !entry.is_null() {
        let next = unsafe { core::ptr::read_unaligned(entry as *const *mut u8) };
        let name_ptr = unsafe { core::ptr::read_unaligned(entry.add(8) as *const *const u8) };
        let rtype = unsafe { core::ptr::read_unaligned(entry.add(16) as *const u16) };

        let name = if !name_ptr.is_null() {
            bytes_to_str(name_ptr, 256)
        } else {
            ByteStr::empty()
        };

        let type_s = dns_type_str(rtype);
        println!("{:<50} {:<8}", name, type_s);
        entry = next;
    }

    if !entry_list.is_null() {
        unsafe { let _ = dns_record_list_free(entry_list, 1); };
    }
    Ok(())
}

fn dns_type_str(t: u16) -> &'static str {
    match t {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA",
        12 => "PTR", 15 => "MX", 16 => "TXT", 28 => "AAAA",
        33 => "SRV", _ => "?",
    }
}

fn bytes_to_str(ptr: *const u8, max: usize) -> ByteStr {
    let mut s = ByteStr::new();
    for i in 0..max {
        let b = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if b == 0 { break; }
        s.push(b);
    }
    s
}

struct ByteStr { buf: [u8; 128], len: usize }
impl ByteStr {
    fn new() -> Self { Self { buf: [0u8; 128], len: 0 } }
    fn empty() -> Self { Self::new() }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for ByteStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
