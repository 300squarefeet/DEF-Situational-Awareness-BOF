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
    Technique { id: "T1016", name: "System Network Configuration Discovery", tactic: "Discovery" },
];

const AF_UNSPEC: u32 = 0;
const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const GAA_FLAG_INCLUDE_PREFIX: u32 = 0x0010;

dfr_fn!(
    get_adapters_addresses(
        family: u32,
        flags: u32,
        reserved: *mut core::ffi::c_void,
        adapter_addresses: *mut u8,
        out_buf_len: *mut u32,
    ) -> u32,
    module = "iphlpapi.dll",
    api    = "GetAdaptersAddresses"
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
    let mut size: u32 = 16384;
    let mut buf: Vec<u8> = Vec::new();

    // Two-pass: first call to get required size, second to fill
    loop {
        buf.resize(size as usize, 0u8);
        let rc = unsafe {
            get_adapters_addresses(
                AF_UNSPEC,
                GAA_FLAG_INCLUDE_PREFIX,
                core::ptr::null_mut(),
                buf.as_mut_ptr(),
                &mut size,
            )
        }.map_err(|_| "GetAdaptersAddresses resolve failed")?;

        match rc {
            ERROR_SUCCESS => break,
            ERROR_BUFFER_OVERFLOW => continue,
            _ => return Err("GetAdaptersAddresses failed"),
        }
    }

    // IP_ADAPTER_ADDRESSES layout (x64):
    // +0   Length u32
    // +4   IfIndex u32
    // +8   Next *mut Self
    // +16  AdapterName *mut i8 (ANSI GUID)
    // +24  FirstUnicastAddress *mut IP_ADAPTER_UNICAST_ADDRESS
    // +32  FirstAnycastAddress
    // +40  FirstMulticastAddress
    // +48  FirstDnsServerAddress
    // +56  DnsSuffix *mut u16
    // +64  Description *mut u16
    // +72  FriendlyName *mut u16
    // +80  PhysicalAddress [u8;8]
    // +88  PhysicalAddressLength u32
    // +92  Flags u32
    // +96  Mtu u32
    // +100 IfType u32
    // +104 OperStatus i32

    let mut adapter = buf.as_ptr();
    while !adapter.is_null() {
        let next = unsafe { core::ptr::read_unaligned(adapter.add(8) as *const *const u8) };
        let friendly_name_ptr = unsafe { core::ptr::read_unaligned(adapter.add(72) as *const *const u16) };
        let phys_len = unsafe { core::ptr::read_unaligned(adapter.add(88) as *const u32) } as usize;
        let phys_ptr = unsafe { adapter.add(80) };

        let friendly = wide_to_str(friendly_name_ptr, 64);
        let mac = fmt_mac(phys_ptr, phys_len.min(8));
        println!("Adapter: {}", friendly);
        println!("  MAC: {}", mac);

        // Walk unicast addresses
        let mut uni = unsafe { core::ptr::read_unaligned(adapter.add(24) as *const *const u8) };
        while !uni.is_null() {
            // IP_ADAPTER_UNICAST_ADDRESS layout:
            // +0  Length u32
            // +8  Next *
            // +16 Address SOCKET_ADDRESS { lpSockaddr: *mut SOCKADDR, iSockaddrLength: i32 }
            //     SOCKET_ADDRESS.lpSockaddr @ +16
            let next_uni = unsafe { core::ptr::read_unaligned(uni.add(8) as *const *const u8) };
            let sockaddr = unsafe { core::ptr::read_unaligned(uni.add(16) as *const *const u8) };
            if !sockaddr.is_null() {
                let family = unsafe { core::ptr::read_unaligned(sockaddr as *const u16) };
                if family == 2 {
                    let addr = unsafe { core::ptr::read_unaligned(sockaddr.add(4) as *const [u8; 4]) };
                    println!("  IPv4: {}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
                } else if family == 23 {
                    println!("  IPv6: (present)");
                }
            }
            uni = next_uni;
        }
        adapter = next;
    }
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

fn fmt_mac(ptr: *const u8, len: usize) -> MacStr {
    let mut s = MacStr::new();
    for i in 0..len {
        let b = unsafe { *ptr.add(i) };
        if i > 0 { s.push(b':'); }
        let hex = b"0123456789abcdef";
        s.push(hex[(b >> 4) as usize]);
        s.push(hex[(b & 0xf) as usize]);
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

struct MacStr { buf: [u8; 24], len: usize }
impl MacStr {
    fn new() -> Self { Self { buf: [0u8; 24], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for MacStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
