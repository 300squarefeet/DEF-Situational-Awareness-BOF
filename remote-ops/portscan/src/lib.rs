// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! TCP connect-scan via non-blocking WSASocket + select.
//!
//! Args: <target-IPv4> <ports-csv> [timeout-ms]
//!   ports-csv : "22,80,443" or "8000-8005,3389"
//! Defaults: timeout = 800ms.
//!
//! OPSEC notes:
//! - randomized port iteration (LCG seeded from KUSER_SHARED_DATA.TickCount)
//!   so packet captures don't show a predictable left-to-right sweep.
//! - never logs the full port list; emits only the OPEN ports.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
];

const AF_INET:        i32 = 2;
const SOCK_STREAM:    i32 = 1;
const IPPROTO_TCP:    i32 = 6;
const FIONBIO:        u32 = 0x8004667E;
const INVALID_SOCKET: usize = !0usize;
const WSAEWOULDBLOCK: i32 = 10035;

#[repr(C)]
struct Timeval { tv_sec: i32, tv_usec: i32 }

#[repr(C)]
struct FdSet { count: u32, array: [usize; 64] }

#[repr(C)]
struct WsaData { _opaque: [u8; 408] }

#[repr(C)]
struct SockAddrIn {
    sin_family: i16,
    sin_port: u16,        // network byte order
    sin_addr: u32,        // network byte order
    sin_zero: [u8; 8],
}

dfr_fn!(
    wsa_startup(version: u16, data: *mut WsaData) -> i32,
    module = "ws2_32.dll",
    api    = "WSAStartup"
);

dfr_fn!(
    wsa_cleanup() -> i32,
    module = "ws2_32.dll",
    api    = "WSACleanup"
);

dfr_fn!(
    wsa_get_last_error() -> i32,
    module = "ws2_32.dll",
    api    = "WSAGetLastError"
);

dfr_fn!(
    socket_(af: i32, ty: i32, proto: i32) -> usize,
    module = "ws2_32.dll",
    api    = "socket"
);

dfr_fn!(
    closesocket(s: usize) -> i32,
    module = "ws2_32.dll",
    api    = "closesocket"
);

dfr_fn!(
    ioctlsocket(s: usize, cmd: u32, argp: *mut u32) -> i32,
    module = "ws2_32.dll",
    api    = "ioctlsocket"
);

dfr_fn!(
    connect_(s: usize, name: *const SockAddrIn, namelen: i32) -> i32,
    module = "ws2_32.dll",
    api    = "connect"
);

dfr_fn!(
    select_(
        nfds: i32, readfds: *mut FdSet, writefds: *mut FdSet,
        exceptfds: *mut FdSet, timeout: *const Timeval,
    ) -> i32,
    module = "ws2_32.dll",
    api    = "select"
);

dfr_fn!(
    inet_addr(cp: *const i8) -> u32,
    module = "ws2_32.dll",
    api    = "inet_addr"
);

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}


fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let target_ip = String::from(parser.get_str());
    let ports_csv = String::from(parser.get_str());
    let timeout_s = String::from(parser.get_str());
    let target_ip = target_ip.as_str();
    let ports_csv = ports_csv.as_str();
    let timeout_s = timeout_s.as_str();

    if target_ip.is_empty() || ports_csv.is_empty() {
        return Err("usage: portscan <ip> <ports-csv> [timeout-ms]");
    }

    let timeout_ms: u32 = parse_u32(timeout_s).unwrap_or(800);

    // NUL-terminate target on stack
    let mut ip_buf = [0u8; 32];
    if target_ip.len() >= ip_buf.len() - 1 { return Err("target too long"); }
    ip_buf[..target_ip.len()].copy_from_slice(target_ip.as_bytes());

    // Parse ports into a stack array (max 256 entries)
    let mut ports = [0u16; 256];
    let n_ports = parse_ports(ports_csv, &mut ports);
    if n_ports == 0 { return Err("no valid ports"); }

    // Randomize iteration order via LCG seeded from KUSER_SHARED_DATA tick.
    let seed = unsafe { core::ptr::read_volatile(0x7FFE0320 as *const u32) }
        .wrapping_mul(2654435761);
    fisher_yates_shuffle(&mut ports[..n_ports], seed);

    // Init WS2_32
    let mut wsa = WsaData { _opaque: [0u8; 408] };
    let rc = unsafe { wsa_startup(0x0202, &mut wsa) }.map_err(|_| "WSAStartup resolve")?;
    if rc != 0 { return Err("WSAStartup failed"); }

    let inet = unsafe { inet_addr(ip_buf.as_ptr() as *const i8) }
        .map_err(|_| "inet_addr resolve")?;
    if inet == 0xFFFFFFFF || inet == 0 {
        unsafe { let _ = wsa_cleanup(); };
        return Err("invalid IPv4 (this BOF is IPv4-only)");
    }

    obf! { let scanning = "scanning"; }
    println!("[*] {} {} ports against target", scanning, n_ports);

    let mut open_count = 0u32;
    for &port in &ports[..n_ports] {
        if probe_port(inet, port, timeout_ms) {
            println!("  OPEN  {}/tcp", port);
            open_count += 1;
        }
    }

    unsafe { let _ = wsa_cleanup(); };
    obf! { let done = "scan done"; }
    println!("[+] {} ({} open)", done, open_count);
    Ok(())
}

/// Single non-blocking connect probe with `select` for writable + timeout.
fn probe_port(inet_be: u32, port: u16, timeout_ms: u32) -> bool {
    let s = unsafe { socket_(AF_INET, SOCK_STREAM, IPPROTO_TCP) }.unwrap_or(INVALID_SOCKET);
    if s == INVALID_SOCKET { return false; }

    // Set non-blocking
    let mut nonblocking: u32 = 1;
    let _ = unsafe { ioctlsocket(s, FIONBIO, &mut nonblocking) };

    let sa = SockAddrIn {
        sin_family: AF_INET as i16,
        sin_port: port.to_be(),
        sin_addr: inet_be,
        sin_zero: [0u8; 8],
    };

    let crc = unsafe { connect_(s, &sa, core::mem::size_of::<SockAddrIn>() as i32) }
        .unwrap_or(-1);
    let mut open = false;
    if crc == 0 {
        open = true;
    } else if crc < 0 {
        let err = unsafe { wsa_get_last_error() }.unwrap_or(0);
        if err == WSAEWOULDBLOCK {
            // select() on writefds with timeout
            let mut wr = FdSet { count: 1, array: [0usize; 64] };
            wr.array[0] = s;
            let tv = Timeval { tv_sec: (timeout_ms / 1000) as i32, tv_usec: ((timeout_ms % 1000) * 1000) as i32 };
            let n = unsafe {
                select_(0, core::ptr::null_mut(), &mut wr, core::ptr::null_mut(), &tv)
            }.unwrap_or(0);
            if n > 0 { open = true; }
        }
    }
    let _ = unsafe { closesocket(s) };
    open
}

fn parse_ports(s: &str, out: &mut [u16]) -> usize {
    let mut n = 0usize;
    for part in s.split(',') {
        if let Some((a, b)) = part.split_once('-') {
            let lo = parse_u32(a).unwrap_or(0) as u16;
            let hi = parse_u32(b).unwrap_or(0) as u16;
            if lo == 0 || hi == 0 || lo > hi { continue; }
            for p in lo..=hi {
                if n >= out.len() { return n; }
                out[n] = p; n += 1;
            }
        } else {
            let p = parse_u32(part).unwrap_or(0) as u16;
            if p == 0 { continue; }
            if n >= out.len() { return n; }
            out[n] = p; n += 1;
        }
    }
    n
}

fn parse_u32(s: &str) -> Option<u32> {
    let mut v: u32 = 0;
    let mut any = false;
    for b in s.bytes() {
        if !b.is_ascii_digit() { return None; }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u32)?;
        any = true;
    }
    if any { Some(v) } else { None }
}

/// In-place Fisher–Yates with an LCG. Pure deterministic given seed —
/// good enough for OPSEC-level reordering, not cryptographic randomness.
fn fisher_yates_shuffle(slice: &mut [u16], mut state: u32) {
    let n = slice.len();
    if n < 2 { return; }
    for i in (1..n).rev() {
        // LCG step (Numerical Recipes constants)
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        let j = (state as usize) % (i + 1);
        slice.swap(i, j);
    }
}
