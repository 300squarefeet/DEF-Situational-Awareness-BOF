// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Display Windows version, architecture, and current user/computer context.
//!
//! Uses RtlGetVersion (ntdll.dll) for accurate OS version (bypasses compat shims).
//! Also calls GetSystemInfo for architecture and GetUserNameA / GetComputerNameA.
//!
//! RTL_OSVERSIONINFOW layout (276 bytes):
//!   dwOSVersionInfoSize(u32@0), dwMajorVersion(u32@4), dwMinorVersion(u32@8),
//!   dwBuildNumber(u32@12), dwPlatformId(u32@16), szCSDVersion([u16;128]@20)
//!
//! SYSTEM_INFO layout: wProcessorArchitecture(u16@0)
//!   9=AMD64, 6=IA64, 0=x86, 12=ARM64
//!
//! Args: none
//!
//! MITRE ATT&CK: T1082 (System Information Discovery)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1082",
        name: "System Information Discovery",
        tactic: "Discovery",
    },
];

dfr_fn!(
    rtl_get_version(lp_version_information: *mut u8) -> i32,
    module = "ntdll.dll",
    api    = "RtlGetVersion"
);

dfr_fn!(
    get_system_info(lp_system_info: *mut u8) -> (),
    module = "kernel32.dll",
    api    = "GetSystemInfo"
);

dfr_fn!(
    get_user_name_a(lp_buffer: *mut u8, pcb_buffer: *mut u32) -> i32,
    module = "advapi32.dll",
    api    = "GetUserNameA"
);

dfr_fn!(
    get_computer_name_a(lp_buffer: *mut u8, n_size: *mut u32) -> i32,
    module = "kernel32.dll",
    api    = "GetComputerNameA"
);

/// Map major.minor.build to a product name string.
fn windows_name(major: u32, minor: u32, build: u32) -> &'static str {
    match (major, minor) {
        (10, 0) if build >= 22000 => "Windows 11",
        (10, 0)                   => "Windows 10",
        (6, 3)                    => "Windows 8.1",
        (6, 2)                    => "Windows 8",
        (6, 1)                    => "Windows 7",
        (6, 0)                    => "Windows Vista",
        (5, 2)                    => "Windows Server 2003 / XP x64",
        (5, 1)                    => "Windows XP",
        _                         => "Windows (unknown)",
    }
}

fn arch_name(arch: u16) -> &'static str {
    match arch {
        9  => "x64 (AMD64)",
        6  => "IA64",
        0  => "x86",
        12 => "ARM64",
        _  => "unknown",
    }
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
    // RTL_OSVERSIONINFOW — 276 bytes
    let mut osver = [0u8; 276];
    // dwOSVersionInfoSize = 276
    unsafe { core::ptr::write_unaligned(osver.as_mut_ptr() as *mut u32, 276u32) };

    let _ = unsafe { rtl_get_version(osver.as_mut_ptr()) }
        .map_err(|_| "resolve failed")?;

    let major: u32 = unsafe { core::ptr::read_unaligned(osver.as_ptr().add(4)  as *const u32) };
    let minor: u32 = unsafe { core::ptr::read_unaligned(osver.as_ptr().add(8)  as *const u32) };
    let build: u32 = unsafe { core::ptr::read_unaligned(osver.as_ptr().add(12) as *const u32) };

    let name = windows_name(major, minor, build);

    // SYSTEM_INFO — read wProcessorArchitecture at offset 0
    let mut sysinfo = [0u8; 64];
    let _ = unsafe { get_system_info(sysinfo.as_mut_ptr()) }
        .map_err(|_| "resolve failed")?;
    let arch: u16 = unsafe { core::ptr::read_unaligned(sysinfo.as_ptr() as *const u16) };

    // GetComputerNameA
    let mut comp_buf = [0u8; 256];
    let mut comp_len: u32 = 255;
    let _ = unsafe { get_computer_name_a(comp_buf.as_mut_ptr(), &mut comp_len) };
    let comp_str = cstr_to_str(comp_buf.as_ptr(), comp_len as usize);

    // GetUserNameA
    let mut user_buf = [0u8; 256];
    let mut user_len: u32 = 255;
    let _ = unsafe { get_user_name_a(user_buf.as_mut_ptr(), &mut user_len) };
    let user_str = cstr_to_str(user_buf.as_ptr(), user_len as usize);

    println!("WINDOWS VERSION INFORMATION");
    println!("{}", "--------------------------------------------");
    println!("  OS          : {} ({}.{}, build {})", name, major, minor, build);
    println!("  Architecture: {}", arch_name(arch));
    println!("  Computer    : {}", comp_str);
    println!("  User        : {}", user_str);
    println!("{}", "--------------------------------------------");

    Ok(())
}

fn cstr_to_str(ptr: *const u8, max: usize) -> ByteStr {
    let mut s = ByteStr::new();
    if ptr.is_null() { return s; }
    for i in 0..max {
        let b = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if b == 0 { break; }
        s.push(b);
    }
    s
}

struct ByteStr { buf: [u8; 256], len: usize }
impl ByteStr {
    fn new() -> Self { Self { buf: [0u8; 256], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for ByteStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
