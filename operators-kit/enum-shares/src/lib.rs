// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};
use alloc::string::String;

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1135", name: "Network Share Discovery", tactic: "Discovery" },
];

const NERR_SUCCESS:           u32 = 0u32;
const MAX_PREFERRED_LENGTH:   u32 = 0xFFFFFFFFu32;

// Share types
const STYPE_DISKTREE:  u32 = 0u32;
const STYPE_PRINTQ:    u32 = 1u32;
const STYPE_DEVICE:    u32 = 2u32;
const STYPE_IPC:       u32 = 3u32;
const STYPE_SPECIAL:   u32 = 0x80000000u32;

dfr_fn!(
    net_share_enum(
        servername: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmax: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resume: *mut u32
    ) -> u32,
    module = "netapi32.dll",
    api    = "NetShareEnum"
);

dfr_fn!(
    net_api_buffer_free(buf: *mut u8) -> u32,
    module = "netapi32.dll",
    api    = "NetApiBufferFree"
);

fn share_type_str(t: u32) -> &'static str {
    match t & 0x7FFFFFFFu32 {
        0 => "DISK",
        1 => "PRINT",
        2 => "DEVICE",
        3 => "IPC",
        _ => "OTHER",
    }
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

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    // Optional server arg — empty means local
    let srv_s = String::from(parser.get_str());
    let server_arg: Option<&str> = if srv_s.is_empty() { None } else { Some(srv_s.as_str()) };

    // Build wide server name if provided
    let mut wide_server = [0u16; 256];
    let server_ptr: *const u16 = if let Some(srv) = server_arg {
        let bytes = srv.as_bytes();
        let n = bytes.len().min(255);
        for (i, &b) in bytes[..n].iter().enumerate() {
            wide_server[i] = b as u16;
        }
        wide_server[n] = 0;
        wide_server.as_ptr()
    } else {
        core::ptr::null()
    };

    let target = server_arg.unwrap_or("(local)");
    println!("NETWORK SHARES on {}:", target);
    println!("{}", "--------------------------------------------");

    let mut buf_ptr: *mut u8 = core::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume: u32 = 0;

    let rc = unsafe {
        net_share_enum(
            server_ptr,
            1u32,
            &mut buf_ptr,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            &mut resume,
        )
    }.map_err(|_| "share enum failed")?;

    if rc != NERR_SUCCESS {
        return Err("share enum error");
    }

    if buf_ptr.is_null() {
        return Err("null buf");
    }

    // SHARE_INFO_1 stride = 24 bytes (x64):
    //   offset  0: shi1_netname  (*const u16, 8 bytes)
    //   offset  8: shi1_type     (u32)
    //   offset 12: _pad          (4 bytes)
    //   offset 16: shi1_remark   (*const u16, 8 bytes)
    for i in 0..entries_read as usize {
        let entry_base = unsafe { buf_ptr.add(i * 24) };

        let name_ptr = unsafe {
            let lo = core::ptr::read_volatile(entry_base.add(0)) as u64;
            let hi = core::ptr::read_volatile(entry_base.add(1)) as u64;
            let raw = u64::from_le_bytes([
                core::ptr::read_volatile(entry_base.add(0)),
                core::ptr::read_volatile(entry_base.add(1)),
                core::ptr::read_volatile(entry_base.add(2)),
                core::ptr::read_volatile(entry_base.add(3)),
                core::ptr::read_volatile(entry_base.add(4)),
                core::ptr::read_volatile(entry_base.add(5)),
                core::ptr::read_volatile(entry_base.add(6)),
                core::ptr::read_volatile(entry_base.add(7)),
            ]);
            raw as *const u16
        };

        let stype = unsafe {
            u32::from_le_bytes([
                core::ptr::read_volatile(entry_base.add(8)),
                core::ptr::read_volatile(entry_base.add(9)),
                core::ptr::read_volatile(entry_base.add(10)),
                core::ptr::read_volatile(entry_base.add(11)),
            ])
        };

        let remark_ptr = unsafe {
            let raw = u64::from_le_bytes([
                core::ptr::read_volatile(entry_base.add(16)),
                core::ptr::read_volatile(entry_base.add(17)),
                core::ptr::read_volatile(entry_base.add(18)),
                core::ptr::read_volatile(entry_base.add(19)),
                core::ptr::read_volatile(entry_base.add(20)),
                core::ptr::read_volatile(entry_base.add(21)),
                core::ptr::read_volatile(entry_base.add(22)),
                core::ptr::read_volatile(entry_base.add(23)),
            ]);
            raw as *const u16
        };

        let name = wide_to_str(name_ptr, 64);
        let remark = wide_to_str(remark_ptr, 64);
        let type_str = share_type_str(stype);
        let special = if stype & STYPE_SPECIAL != 0 { " (SPECIAL)" } else { "" };

        println!("  [{}{}] \\{}  {}", type_str, special, name, remark);
    }

    unsafe { let _ = net_api_buffer_free(buf_ptr); };
    println!("  {} share(s) listed", entries_read);
    Ok(())
}
