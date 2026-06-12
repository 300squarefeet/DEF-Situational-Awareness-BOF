// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Enumerate logical drives with type and free-space information.
//! No arguments required.
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
];

dfr_fn!(
    get_logical_drive_strings_a(buf_len: u32, buf: *mut u8) -> u32,
    module = "kernel32.dll",
    api    = "GetLogicalDriveStringsA"
);

dfr_fn!(
    get_drive_type_a(root: *const i8) -> u32,
    module = "kernel32.dll",
    api    = "GetDriveTypeA"
);

dfr_fn!(
    get_disk_free_space_ex_a(
        dir:        *const i8,
        free_avail: *mut u64,
        total:      *mut u64,
        total_free: *mut u64
    ) -> i32,
    module = "kernel32.dll",
    api    = "GetDiskFreeSpaceExA"
);

fn drive_type_str(t: u32) -> &'static str {
    match t {
        2 => "Removable",
        3 => "Fixed",
        4 => "Remote",
        5 => "CDROM",
        6 => "RAMDisk",
        _ => "Unknown",
    }
}

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {}
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // Buffer for double-NUL terminated list: "C:\\\0D:\\\0\0"
    let mut buf = [0u8; 256];
    let written = unsafe {
        get_logical_drive_strings_a(buf.len() as u32, buf.as_mut_ptr())
    }.map_err(|_| "drive list failed")?;

    if written == 0 {
        return Err("no drives returned");
    }

    println!("{:<12} {:<10} {}", obf!("Drive"), obf!("Type"), obf!("Space"));
    println!("{}", "--------------------------------------------");

    let mut pos = 0usize;
    while pos < buf.len() {
        // Find next NUL to get this drive string
        let start = pos;
        while pos < buf.len() && buf[pos] != 0 {
            pos += 1;
        }
        if pos == start {
            break; // double-NUL — end of list
        }
        let drive_bytes = &buf[start..pos];
        pos += 1; // skip NUL

        // Build a NUL-terminated [i8; 8] buffer for the drive root (e.g. "C:\\\0")
        let mut root_buf = [0i8; 8];
        let copy_len = drive_bytes.len().min(7);
        for (i, &b) in drive_bytes[..copy_len].iter().enumerate() {
            root_buf[i] = b as i8;
        }
        root_buf[copy_len] = 0;

        let drive_type = unsafe {
            get_drive_type_a(root_buf.as_ptr())
        }.unwrap_or(0);

        let type_str = drive_type_str(drive_type);

        // Build drive letter display (ASCII-safe)
        let drive_letter = if !drive_bytes.is_empty() { drive_bytes[0] as char } else { '?' };

        // Query space for Fixed (3) or Remote (4) drives
        if drive_type == 3 || drive_type == 4 {
            let mut free_avail: u64 = 0;
            let mut total:      u64 = 0;
            let mut total_free: u64 = 0;
            let ok = unsafe {
                get_disk_free_space_ex_a(
                    root_buf.as_ptr(),
                    &mut free_avail,
                    &mut total,
                    &mut total_free,
                )
            }.unwrap_or(0);
            if ok != 0 {
                let total_gb = total      / (1024 * 1024 * 1024);
                let free_gb  = free_avail / (1024 * 1024 * 1024);
                println!(
                    "  [{}] {}\\   {:<10} total={} GB  free={} GB",
                    drive_letter, drive_letter, type_str, total_gb, free_gb
                );
            } else {
                println!("  [{}] {}\\   {}", drive_letter, drive_letter, type_str);
            }
        } else {
            println!("  [{}] {}\\   {}", drive_letter, drive_letter, type_str);
        }
    }

    Ok(())
}
