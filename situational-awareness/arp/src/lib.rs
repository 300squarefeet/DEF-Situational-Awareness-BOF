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
    Technique { id: "T1018", name: "Remote System Discovery", tactic: "Discovery" },
];

// AF_INET = 2, AF_INET6 = 23, AF_UNSPEC = 0
const AF_UNSPEC: u16 = 0;
const ERROR_SUCCESS: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

// MIB_IPNET_ROW2 physical address is 32 bytes; PhysAddrLength is ULONG.
// We only need fields: Address (SOCKADDR_INET = 28 bytes), PhysAddr (32 bytes + len).
// Use raw pointer arithmetic rather than importing the full struct.
const ROW2_SIZE: usize = 80; // conservative upper bound for MIB_IPNET_ROW2

dfr_fn!(
    get_ip_net_table2(family: u16, table: *mut *mut u8) -> u32,
    module = "iphlpapi.dll",
    api    = "GetIpNetTable2"
);

dfr_fn!(
    free_mib_table(memory: *mut u8) -> (),
    module = "iphlpapi.dll",
    api    = "FreeMibTable"
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
    let mut table: *mut u8 = core::ptr::null_mut();
    let rc = unsafe { get_ip_net_table2(AF_UNSPEC, &mut table as *mut *mut u8) }
        .map_err(|_| "GetIpNetTable2 resolve failed")?;
    if rc != ERROR_SUCCESS {
        return Err("GetIpNetTable2 failed");
    }
    if table.is_null() {
        return Err("null table");
    }
    // MIB_IPNET_TABLE2 layout: ULONG NumEntries @ 0, then Table[0] @ 8 (aligned)
    let num_entries = unsafe { core::ptr::read_unaligned(table as *const u32) } as usize;
    println!("ARP TABLE ({} entries):", num_entries);
    println!("{:<20} {:<20} {:<10}", "IP Address", "MAC Address", "Type");
    println!("{}", "------------------------------------------------------------");

    // Table entries start at offset 8 (4 bytes NumEntries + 4 bytes padding)
    let entries_ptr = unsafe { table.add(8) };

    for i in 0..num_entries {
        // Each entry: SOCKADDR_INET Address(28) + PhysAddr[32] + PhysAddrLen(4) + State(4) + ...
        // offset 0  = SOCKADDR_INET (family u16 @ 0, then IPv4 addr @ 4 or IPv6 @ 8)
        // offset 28 = PhysAddr [u8; 32]
        // offset 60 = PhysAddrLength u32
        // offset 64 = State u32
        let row = unsafe { entries_ptr.add(i * ROW2_SIZE) };
        let family = unsafe { core::ptr::read_unaligned(row as *const u16) };
        // State: 0=Unreachable, 1=Incomplete, 2=Probe, 3=Delay,
        //        4=Stale, 5=Reachable, 6=Permanent, 7=TooOld
        let state = unsafe { core::ptr::read_unaligned(row.add(64) as *const u32) };
        let phys_len = unsafe { core::ptr::read_unaligned(row.add(60) as *const u32) } as usize;

        let ip_str = fmt_ip(row, family);
        let mac_str = fmt_mac(unsafe { row.add(28) }, phys_len.min(6));
        let state_str = match state {
            5 => "Reachable",
            6 => "Permanent",
            4 => "Stale",
            2 => "Probe",
            _ => "Other",
        };
        println!("{:<20} {:<20} {:<10}", ip_str, mac_str, state_str);
    }

    unsafe { let _ = free_mib_table(table); };
    Ok(())
}

fn fmt_ip(row: *const u8, family: u16) -> IpStr {
    let mut s = IpStr::new();
    if family == 2 {
        // IPv4: SOCKADDR_IN — port @ 2..4, addr @ 4..8
        let addr = unsafe { core::ptr::read_unaligned(row.add(4) as *const [u8; 4]) };
        s.write_fmt_args(format_args!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]));
    } else {
        for b in b"IPv6" {
            if s.len < s.buf.len() { s.buf[s.len] = *b; s.len += 1; }
        }
    }
    s
}

fn fmt_mac(ptr: *const u8, len: usize) -> MacStr {
    let mut s = MacStr::new();
    for i in 0..len {
        let b = unsafe { *ptr.add(i) };
        if i > 0 { s.push(b':'); }
        s.push_hex(b);
    }
    s
}

// Minimal stack-allocated display strings
struct IpStr { buf: [u8; 40], len: usize }
impl IpStr {
    fn new() -> Self { Self { buf: [0u8; 40], len: 0 } }
    fn write_fmt_args(&mut self, args: core::fmt::Arguments) {
        use core::fmt::Write;
        let _ = self.write_fmt(args);
    }
}
impl core::fmt::Write for IpStr {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
        }
        Ok(())
    }
}
impl core::fmt::Display for IpStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}

struct MacStr { buf: [u8; 24], len: usize }
impl MacStr {
    fn new() -> Self { Self { buf: [0u8; 24], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
    fn push_hex(&mut self, b: u8) {
        const HEX: &[u8] = b"0123456789abcdef";
        self.push(HEX[(b >> 4) as usize]);
        self.push(HEX[(b & 0xf) as usize]);
    }
}
impl core::fmt::Display for MacStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
