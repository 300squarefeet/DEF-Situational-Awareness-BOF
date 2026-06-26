// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1016", name: "System Network Configuration Discovery", tactic: "Discovery" },
];

const AF_UNSPEC: u16 = 0;
const ERROR_SUCCESS: u32 = 0;

dfr_fn!(
    get_ip_forward_table2(family: u16, table: *mut *mut u8) -> u32,
    module = "iphlpapi.dll",
    api    = "GetIpForwardTable2"
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
    let rc = unsafe { get_ip_forward_table2(AF_UNSPEC, &mut table) }
        .map_err(|_| "GetIpForwardTable2 resolve failed")?;
    if rc != ERROR_SUCCESS {
        return Err("GetIpForwardTable2 failed");
    }
    if table.is_null() {
        return Err("null table");
    }

    // MIB_IPFORWARD_TABLE2: ULONG NumEntries @ 0, entries @ 8
    // MIB_IPFORWARD_ROW2 (x64, simplified field access):
    // +0   InterfaceLuid  (ULONG64)
    // +8   InterfaceIndex (ULONG)
    // +12  DestinationPrefix { Address(SOCKADDR_INET=28), PrefixLength(u8) } → dest addr @ +12
    // +40  NextHop SOCKADDR_INET → @ +40+0 (family u16), addr @ +40+4
    // +68  SitePrefixLength u8
    // +72  ValidLifetime u32
    // +76  PreferredLifetime u32
    // +80  Metric u32
    // +84  Protocol u32

    let num = unsafe { core::ptr::read_unaligned(table as *const u32) } as usize;
    let row_ptr = unsafe { table.add(8) };

    // MIB_IPFORWARD_ROW2 size = 104 bytes (from Windows SDK)
    const ROW_SIZE: usize = 104;

    println!("ROUTING TABLE ({} entries):", num);
    println!("{:<20} {:<6} {:<20} {:<8}", "Destination/Mask", "Pfx", "NextHop", "Metric");
    println!("{}", "-----------------------------------------------------");

    for i in 0..num {
        let row = unsafe { row_ptr.add(i * ROW_SIZE) };
        // DestinationPrefix: family at +12, IPv4 addr at +16
        let dest_family = unsafe { core::ptr::read_unaligned(row.add(12) as *const u16) };
        let prefix_len  = unsafe { core::ptr::read_unaligned(row.add(40) as *const u8) };
        // NextHop SOCKADDR_INET: family @ +44, IPv4 @ +48
        let hop_family  = unsafe { core::ptr::read_unaligned(row.add(44) as *const u16) };
        let metric      = unsafe { core::ptr::read_unaligned(row.add(96) as *const u32) };

        let dest = if dest_family == 2 {
            let a = unsafe { core::ptr::read_unaligned(row.add(16) as *const [u8; 4]) };
            fmt_ipv4(a)
        } else {
            fmt_na()
        };

        let hop = if hop_family == 2 {
            let a = unsafe { core::ptr::read_unaligned(row.add(48) as *const [u8; 4]) };
            fmt_ipv4(a)
        } else {
            fmt_na()
        };

        println!("{:<20} {:<6} {:<20} {:<8}", dest, prefix_len, hop, metric);
    }

    unsafe { let _ = free_mib_table(table); };
    Ok(())
}

fn fmt_ipv4(a: [u8; 4]) -> IpStr {
    let mut s = IpStr::new();
    use core::fmt::Write;
    let _ = write!(s, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
    s
}

fn fmt_na() -> IpStr {
    let mut s = IpStr::new();
    for b in b"(IPv6)" { s.buf[s.len] = *b; s.len += 1; }
    s
}

struct IpStr { buf: [u8; 20], len: usize }
impl IpStr { fn new() -> Self { Self { buf: [0u8; 20], len: 0 } } }
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
