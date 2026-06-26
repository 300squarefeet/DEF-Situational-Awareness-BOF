// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! ICMP ping sweep to enumerate active hosts in a /24 subnet.
//! Args: <cidr>  e.g. "192.168.1.0/24"
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::string::String;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1018", name: "Remote System Discovery", tactic: "Discovery" },
];

dfr_fn!(
    icmp_create_file() -> usize,
    module = "icmp.dll",
    api    = "IcmpCreateFile"
);

dfr_fn!(
    icmp_send_echo(
        handle:     usize,
        dest:       u32,
        req_data:   *const u8,
        req_size:   u16,
        opts:       usize,
        reply:      *mut u8,
        reply_size: u32,
        timeout:    u32
    ) -> u32,
    module = "icmp.dll",
    api    = "IcmpSendEcho"
);

dfr_fn!(
    icmp_close_handle(handle: usize) -> i32,
    module = "icmp.dll",
    api    = "IcmpCloseHandle"
);

dfr_fn!(
    wsa_startup(version: u16, data: *mut u8) -> i32,
    module = "ws2_32.dll",
    api    = "WSAStartup"
);

dfr_fn!(
    inet_addr(cp: *const i8) -> u32,
    module = "ws2_32.dll",
    api    = "inet_addr"
);

/// Copy a &str into a NUL-terminated [u8; 64] stack buffer.
fn to_cstr_64(s: &str) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let n = s.len().min(63);
    buf[..n].copy_from_slice(&s.as_bytes()[..n]);
    buf[n] = 0;
    buf
}

/// Parse a decimal u32 from a byte slice (no std).
fn parse_u32(s: &[u8]) -> Option<u32> {
    let mut acc: u32 = 0;
    if s.is_empty() { return None; }
    for &b in s {
        let d = b.wrapping_sub(b'0');
        if d > 9 { return None; }
        acc = acc.checked_mul(10)?.checked_add(d as u32)?;
    }
    Some(acc)
}

/// Print an IPv4 address from a u32 in host byte order.
fn print_ip(host: u32) {
    let a = (host >> 24) & 0xFF;
    let b = (host >> 16) & 0xFF;
    let c = (host >> 8)  & 0xFF;
    let d =  host        & 0xFF;
    println!("  UP: {}.{}.{}.{}", a, b, c, d);
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {}
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let cidr_s = String::from(parser.get_str());
    let cidr = cidr_s.as_str();
    if cidr.is_empty() { return Err("usage: enum-active-hosts <cidr>"); }

    // Split on '/'
    let slash = cidr.as_bytes().iter().position(|&b| b == b'/')
        .ok_or("invalid CIDR")?;
    let ip_part = &cidr[..slash];
    let _prefix  = &cidr[slash + 1..];

    // WSAStartup (needed for inet_addr on some hosts)
    let mut wsa_data = [0u8; 408];
    unsafe { wsa_startup(0x0202, wsa_data.as_mut_ptr()) }
        .map_err(|_| "network init failed")?;

    // Convert IP string to u32 (network byte order) via inet_addr
    let ip_cstr = to_cstr_64(ip_part);
    let ip_be = unsafe { inet_addr(ip_cstr.as_ptr() as *const i8) }
        .map_err(|_| "addr parse failed")?;

    // ip_be is in network byte order; convert to host order for arithmetic
    let ip_host = u32::from_be(ip_be);

    // /24: mask off last octet
    let net_host = ip_host & 0xFFFFFF00u32;

    // Open ICMP handle
    let h = unsafe { icmp_create_file() }
        .map_err(|_| "icmp handle failed")?;
    if h == 0 || h == !0usize {
        return Err("icmp handle invalid");
    }

    let req_data = [0u8; 32];
    let mut up_count: u32 = 0;

    println!("{}", obf!("[*] Scanning /24 subnet..."));

    for i in 1u32..=254 {
        let host_host = net_host | i;
        // Back to network byte order for IcmpSendEcho dest
        let dest_be = host_host.to_be();

        let mut reply_buf = [0u8; 40];
        let sent = unsafe {
            icmp_send_echo(
                h,
                dest_be,
                req_data.as_ptr(),
                req_data.len() as u16,
                0,
                reply_buf.as_mut_ptr(),
                reply_buf.len() as u32,
                500,
            )
        }.unwrap_or(0);

        if sent > 0 {
            // ICMP_ECHO_REPLY: bytes 0-3 = Address, bytes 4-7 = Status (0 = success)
            let status = u32::from_le_bytes([
                reply_buf[4], reply_buf[5], reply_buf[6], reply_buf[7],
            ]);
            if status == 0 {
                print_ip(host_host);
                up_count += 1;
            }
        }
    }

    unsafe { let _ = icmp_close_handle(h); };

    println!("{} host(s) responded.", up_count);
    Ok(())
}
