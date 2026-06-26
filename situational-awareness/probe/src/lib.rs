// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! TCP port probe with hostname resolution.
//!
//! Args: <target> <ports> [timeout-ms]
//!   target : hostname       ("dc01.corp.local" — DNS resolved via getaddrinfo)
//!            single IPv4   ("192.168.1.6")
//!            or CIDR        ("192.168.1.6/24" — max /20 = 4096 hosts, IPv4 only)
//!   ports  : space-OR-comma separated, supports ranges
//!            "443 445 80"  or  "443,445,80"  or  "8000-8005,3389"
//! Defaults: timeout = 800ms.
//!
//! OPSEC notes:
//! - randomized port iteration (LCG seeded from KUSER_SHARED_DATA.TickCount)
//!   so packet captures don't show a predictable left-to-right sweep.
//! - randomized host iteration (separate LCG seed) when scanning a CIDR
//!   range — defenders watching for sequential .1 .2 .3 sweeps see noise.
//! - never logs the full port list; emits only the OPEN ports.
//! - all sensitive API names (getaddrinfo, freeaddrinfo, etc.) resolved by
//!   hash at runtime via DFR — not present as plaintext strings.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use alloc::vec::Vec;
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
const INADDR_NONE:    u32 = 0xFFFF_FFFF;

// Cap host count to keep scan tractable. /20 = 4096 hosts is the practical
// upper bound for a CS BOF run (4096 × ~5 ports × ~800ms ≈ 27 minutes).
const MAX_HOSTS: u32 = 4096;
const MAX_PORTS: usize = 256;

#[repr(C)]
struct Timeval { tv_sec: i32, tv_usec: i32 }

#[repr(C)]
struct FdSet { count: u32, array: [usize; 64] }

#[repr(C)]
struct WsaData { _opaque: [u8; 408] }

#[repr(C)]
struct SockAddrIn {
    sin_family: i16,
    sin_port:   u16,    // network byte order
    sin_addr:   u32,    // network byte order
    sin_zero:   [u8; 8],
}

/// Subset of `struct addrinfo` that we need. The full struct has more fields
/// after ai_canonname but we only dereference the ones we use.
#[repr(C)]
struct AddrInfoA {
    ai_flags:     i32,
    ai_family:    i32,
    ai_socktype:  i32,
    ai_protocol:  i32,
    ai_addrlen:   usize,
    ai_canonname: *mut i8,
    ai_addr:      *mut SockAddrIn,
    ai_next:      *mut AddrInfoA,
}

// ──────────────────────────── DFR bindings ───────────────────────────────────

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

dfr_fn!(
    getaddrinfo_(
        node:    *const i8,
        service: *const i8,
        hints:   *const AddrInfoA,
        result:  *mut *mut AddrInfoA,
    ) -> i32,
    module = "ws2_32.dll",
    api    = "getaddrinfo"
);

dfr_fn!(
    freeaddrinfo_(ai: *mut AddrInfoA) -> (),
    module = "ws2_32.dll",
    api    = "freeaddrinfo"
);

// ──────────────────────────── Entry point ────────────────────────────────────

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

// ──────────────────────────── Main logic ─────────────────────────────────────

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let target_arg = String::from(parser.get_str());
    let ports_str  = String::from(parser.get_str());
    let timeout_s  = String::from(parser.get_str());
    let target_arg = target_arg.as_str();
    let ports_str  = ports_str.as_str();
    let timeout_s  = timeout_s.as_str();

    if target_arg.is_empty() || ports_str.is_empty() {
        return Err("usage: probe <host-or-ip-or-cidr> <ports> [timeout-ms]");
    }

    let timeout_ms: u32 = parse_u32(timeout_s).unwrap_or(800);

    // Parse ports
    let mut ports = [0u16; MAX_PORTS];
    let n_ports = parse_ports(ports_str, &mut ports);
    if n_ports == 0 { return Err("no valid ports"); }

    // Randomize port order (seeded from KUSER_SHARED_DATA.TickCount)
    let seed_p = unsafe { core::ptr::read_volatile(0x7FFE0320 as *const u32) }
        .wrapping_mul(2654435761);
    fisher_yates_shuffle_u16(&mut ports[..n_ports], seed_p);

    // Init WS2_32
    let mut wsa = WsaData { _opaque: [0u8; 408] };
    let rc = unsafe { wsa_startup(0x0202, &mut wsa) }.map_err(|_| "network init failed")?;
    if rc != 0 { return Err("network init failed"); }

    // Build host list from target arg
    let hosts = match parse_target(target_arg) {
        Ok(h) => h,
        Err(e) => {
            unsafe { let _ = wsa_cleanup(); };
            return Err(e);
        }
    };

    if hosts.is_empty() {
        unsafe { let _ = wsa_cleanup(); };
        return Err("no hosts to scan");
    }

    // Randomize host order with a different LCG seed
    let seed_h = seed_p.wrapping_mul(0x9E3779B1).wrapping_add(0x85EBCA77);
    let mut host_vec = hosts;
    fisher_yates_shuffle_u32(&mut host_vec, seed_h);

    obf! { let scanning = "scanning"; }
    let total_probes = (host_vec.len() as u64) * (n_ports as u64);
    println!("[*] {} {} hosts × {} ports = {} probes",
             scanning, host_vec.len(), n_ports, total_probes);

    let mut open_total = 0u32;
    for &host_be in host_vec.iter() {
        for &port in &ports[..n_ports] {
            if probe_port(host_be, port, timeout_ms) {
                println!("  OPEN  {}.{}.{}.{}:{}/tcp",
                         (host_be) & 0xFF,
                         (host_be >> 8) & 0xFF,
                         (host_be >> 16) & 0xFF,
                         (host_be >> 24) & 0xFF,
                         port);
                open_total += 1;
            }
        }
    }

    unsafe { let _ = wsa_cleanup(); };
    obf! { let done = "scan done"; }
    println!("[+] {} ({} open across {} hosts)", done, open_total, host_vec.len());
    Ok(())
}

// ──────────────────────────── Target parsing ─────────────────────────────────

/// Parse the target string into a list of host IPs (network byte order u32).
/// - If it contains '/' → CIDR (IPv4 only, no DNS).
/// - Else: try inet_addr first; if that fails (INADDR_NONE) → DNS via getaddrinfo.
fn parse_target(target: &str) -> Result<Vec<u32>, &'static str> {
    if let Some((ip_str, prefix_str)) = target.split_once('/') {
        // CIDR path — IPv4 only, no DNS
        let mut ip_buf = [0u8; 64];
        if ip_str.len() >= ip_buf.len() - 1 { return Err("target too long"); }
        ip_buf[..ip_str.len()].copy_from_slice(ip_str.as_bytes());

        let base_be = unsafe { inet_addr(ip_buf.as_ptr() as *const i8) }
            .map_err(|_| "address resolution failed")?;
        if base_be == INADDR_NONE || base_be == 0 {
            return Err("invalid IPv4 for CIDR");
        }

        let prefix = parse_u32(prefix_str).ok_or("bad CIDR prefix")?;
        if prefix == 0 || prefix > 32 { return Err("prefix must be 1-32"); }
        expand_cidr(base_be, prefix)
    } else {
        // Single host — try inet_addr first, then DNS
        let mut host_buf = [0u8; 256];
        if target.len() >= host_buf.len() - 1 { return Err("target too long"); }
        host_buf[..target.len()].copy_from_slice(target.as_bytes());

        let base_be = unsafe { inet_addr(host_buf.as_ptr() as *const i8) }
            .unwrap_or(INADDR_NONE);

        let resolved_be = if base_be != INADDR_NONE && base_be != 0 {
            // Valid dotted-decimal IPv4
            base_be
        } else {
            // Fall back to DNS
            resolve_hostname(host_buf.as_ptr() as *const i8)?
        };

        let mut v = Vec::with_capacity(1);
        v.push(resolved_be);
        Ok(v)
    }
}

/// Resolve a NUL-terminated hostname to an IPv4 address (network byte order)
/// using getaddrinfo with AF_INET hints.
fn resolve_hostname(host: *const i8) -> Result<u32, &'static str> {
    let hints = AddrInfoA {
        ai_flags:     0,
        ai_family:    AF_INET,
        ai_socktype:  SOCK_STREAM,
        ai_protocol:  IPPROTO_TCP,
        ai_addrlen:   0,
        ai_canonname: core::ptr::null_mut(),
        ai_addr:      core::ptr::null_mut(),
        ai_next:      core::ptr::null_mut(),
    };

    let mut result: *mut AddrInfoA = core::ptr::null_mut();
    let rc = unsafe {
        getaddrinfo_(host, core::ptr::null(), &hints, &mut result)
    }.map_err(|_| "address resolution failed")?;

    if rc != 0 || result.is_null() {
        return Err("hostname not resolved");
    }

    // Extract the first IPv4 address
    let addr_be = unsafe {
        let sa = (*result).ai_addr;
        if sa.is_null() {
            let _ = freeaddrinfo_(result);
            return Err("hostname not resolved");
        }
        (*sa).sin_addr
    };

    unsafe { let _ = freeaddrinfo_(result); };
    Ok(addr_be)
}

// ──────────────────────────── CIDR expansion ─────────────────────────────────

/// Expand a CIDR into a Vec<u32> of host IPs in network byte order.
fn expand_cidr(base_be: u32, prefix: u32) -> Result<Vec<u32>, &'static str> {
    let base_host = u32::from_be(base_be);
    let mask_host: u32 = if prefix == 32 {
        0xFFFF_FFFF
    } else {
        (!0u32) << (32 - prefix)
    };
    let net_start_host = base_host & mask_host;
    let host_bits = 32 - prefix;
    if host_bits == 0 {
        // /32 — single host
        let mut v = Vec::with_capacity(1);
        v.push(net_start_host.to_be());
        return Ok(v);
    }
    let count: u64 = 1u64 << host_bits;
    if count > MAX_HOSTS as u64 {
        return Err("CIDR too large (max /20 = 4096 hosts)");
    }
    let mut v: Vec<u32> = Vec::with_capacity(count as usize);
    for i in 0..(count as u32) {
        let host = net_start_host.wrapping_add(i);
        v.push(host.to_be());
    }
    Ok(v)
}

// ──────────────────────────── Port probe ─────────────────────────────────────

/// Single non-blocking connect probe with `select` for writable + timeout.
fn probe_port(inet_be: u32, port: u16, timeout_ms: u32) -> bool {
    let s = unsafe { socket_(AF_INET, SOCK_STREAM, IPPROTO_TCP) }
        .unwrap_or(INVALID_SOCKET);
    if s == INVALID_SOCKET { return false; }

    let mut nonblocking: u32 = 1;
    let _ = unsafe { ioctlsocket(s, FIONBIO, &mut nonblocking) };

    let sa = SockAddrIn {
        sin_family: AF_INET as i16,
        sin_port:   port.to_be(),
        sin_addr:   inet_be,
        sin_zero:   [0u8; 8],
    };

    let crc = unsafe { connect_(s, &sa, core::mem::size_of::<SockAddrIn>() as i32) }
        .unwrap_or(-1);
    let mut open = false;
    if crc == 0 {
        open = true;
    } else if crc < 0 {
        let err = unsafe { wsa_get_last_error() }.unwrap_or(0);
        if err == WSAEWOULDBLOCK {
            let mut wr = FdSet { count: 1, array: [0usize; 64] };
            wr.array[0] = s;
            let tv = Timeval {
                tv_sec:  (timeout_ms / 1000) as i32,
                tv_usec: ((timeout_ms % 1000) * 1000) as i32,
            };
            let n = unsafe {
                select_(0, core::ptr::null_mut(), &mut wr, core::ptr::null_mut(), &tv)
            }.unwrap_or(0);
            if n > 0 { open = true; }
        }
    }
    let _ = unsafe { closesocket(s) };
    open
}

// ──────────────────────────── Helpers ────────────────────────────────────────

/// Parse a port spec accepting BOTH comma AND whitespace AND tabs as
/// delimiters, plus `a-b` ranges per token.
fn parse_ports(s: &str, out: &mut [u16]) -> usize {
    let mut n = 0usize;
    for part in s.split(|c: char| c == ',' || c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        if part.is_empty() { continue; }
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

/// In-place Fisher–Yates with an LCG.
fn fisher_yates_shuffle_u16(slice: &mut [u16], mut state: u32) {
    let n = slice.len();
    if n < 2 { return; }
    for i in (1..n).rev() {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        let j = (state as usize) % (i + 1);
        slice.swap(i, j);
    }
}

fn fisher_yates_shuffle_u32(slice: &mut [u32], mut state: u32) {
    let n = slice.len();
    if n < 2 { return; }
    for i in (1..n).rev() {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        let j = (state as usize) % (i + 1);
        slice.swap(i, j);
    }
}
