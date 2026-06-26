// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
#![no_std]
#![cfg_attr(not(test), no_main)]


use alloc::vec::Vec;

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1049", name: "System Network Connections Discovery", tactic: "Discovery" },
];

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const ERROR_SUCCESS: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

dfr_fn!(
    get_extended_tcp_table(
        tcp_table: *mut u8,
        size: *mut u32,
        order: i32,
        ul_af: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32,
    module = "iphlpapi.dll",
    api    = "GetExtendedTcpTable"
);

dfr_fn!(
    get_extended_udp_table(
        udp_table: *mut u8,
        size: *mut u32,
        order: i32,
        ul_af: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32,
    module = "iphlpapi.dll",
    api    = "GetExtendedUdpTable"
);

// TCP_TABLE_OWNER_PID_ALL = 5, UDP_TABLE_OWNER_PID = 1
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const UDP_TABLE_OWNER_PID: u32 = 1;

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    println!("{:<10} {:<22} {:<22} {:<12} {:<8}", "Proto", "Local", "Remote", "State", "PID");
    println!("{}", "-----------------------------------------------------------------------");
    dump_tcp(AF_INET)?;
    dump_tcp(AF_INET6)?;
    dump_udp(AF_INET)?;
    dump_udp(AF_INET6)?;
    Ok(())
}

fn dump_tcp(af: u32) -> Result<(), &'static str> {
    let buf = alloc_table(af, true)?;
    // MIB_TCPTABLE_OWNER_PID: dwNumEntries u32 @ 0, then rows @ 4
    // MIB_TCPROW_OWNER_PID: State(4) LocalAddr(4) LocalPort(4) RemoteAddr(4) RemotePort(4) PID(4)
    // IPv4 row = 24 bytes; IPv6 row = 56 bytes
    let num = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const u32) } as usize;
    let row_size: usize = if af == AF_INET { 24 } else { 56 };
    let base = unsafe { buf.as_ptr().add(4) };
    for i in 0..num {
        let row = unsafe { base.add(i * row_size) };
        let state = unsafe { core::ptr::read_unaligned(row as *const u32) };
        let pid = unsafe { core::ptr::read_unaligned(row.add(row_size - 4) as *const u32) };
        let proto = if af == AF_INET { "TCP4" } else { "TCP6" };
        let (local, remote) = if af == AF_INET {
            let la = unsafe { core::ptr::read_unaligned(row.add(4) as *const [u8; 4]) };
            let lp = u16::from_be(unsafe { core::ptr::read_unaligned(row.add(8) as *const u16) });
            let ra = unsafe { core::ptr::read_unaligned(row.add(12) as *const [u8; 4]) };
            let rp = u16::from_be(unsafe { core::ptr::read_unaligned(row.add(16) as *const u16) });
            (fmt_addr4(la, lp), fmt_addr4(ra, rp))
        } else {
            (fmt_v6_short(), fmt_v6_short())
        };
        let state_s = tcp_state(state);
        println!("{:<10} {:<22} {:<22} {:<12} {:<8}", proto, local, remote, state_s, pid);
    }
    Ok(())
}

fn dump_udp(af: u32) -> Result<(), &'static str> {
    let buf = alloc_table(af, false)?;
    let num = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const u32) } as usize;
    let row_size: usize = if af == AF_INET { 12 } else { 28 };
    let base = unsafe { buf.as_ptr().add(4) };
    for i in 0..num {
        let row = unsafe { base.add(i * row_size) };
        let pid = unsafe { core::ptr::read_unaligned(row.add(row_size - 4) as *const u32) };
        let proto = if af == AF_INET { "UDP4" } else { "UDP6" };
        let local = if af == AF_INET {
            let la = unsafe { core::ptr::read_unaligned(row as *const [u8; 4]) };
            let lp = u16::from_be(unsafe { core::ptr::read_unaligned(row.add(4) as *const u16) });
            fmt_addr4(la, lp)
        } else {
            fmt_v6_short()
        };
        println!("{:<10} {:<22} {:<22} {:<12} {:<8}", proto, local, "*:*", "-", pid);
    }
    Ok(())
}

fn alloc_table(af: u32, tcp: bool) -> Result<Vec<u8>, &'static str> {
    let mut size: u32 = 4096;
    loop {
        let mut buf: Vec<u8> = alloc::vec![0u8; size as usize];
        let rc = if tcp {
            unsafe { get_extended_tcp_table(buf.as_mut_ptr(), &mut size, 1, af, TCP_TABLE_OWNER_PID_ALL, 0) }
                .map_err(|_| "GetExtendedTcpTable resolve")?
        } else {
            unsafe { get_extended_udp_table(buf.as_mut_ptr(), &mut size, 1, af, UDP_TABLE_OWNER_PID, 0) }
                .map_err(|_| "GetExtendedUdpTable resolve")?
        };
        match rc {
            ERROR_SUCCESS => return Ok(buf),
            ERROR_INSUFFICIENT_BUFFER => continue,
            _ => return Err("table query failed"),
        }
    }
}

fn tcp_state(s: u32) -> &'static str {
    match s {
        1 => "CLOSED", 2 => "LISTEN", 3 => "SYN_SENT", 4 => "SYN_RCVD",
        5 => "ESTAB", 6 => "FIN_WAIT1", 7 => "FIN_WAIT2", 8 => "CLOSE_WAIT",
        9 => "CLOSING", 10 => "LAST_ACK", 11 => "TIME_WAIT", 12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

fn fmt_addr4(addr: [u8; 4], port: u16) -> Addr4Str {
    let mut s = Addr4Str::new();
    use core::fmt::Write;
    let _ = write!(s, "{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], port);
    s
}

fn fmt_v6_short() -> Addr4Str {
    let mut s = Addr4Str::new();
    for b in b"[IPv6]:?" { s.buf[s.len] = *b; s.len += 1; }
    s
}

struct Addr4Str { buf: [u8; 22], len: usize }
impl Addr4Str {
    fn new() -> Self { Self { buf: [0u8; 22], len: 0 } }
}
impl core::fmt::Write for Addr4Str {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
        }
        Ok(())
    }
}
impl core::fmt::Display for Addr4Str {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
