// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1574.007",
        name: "Path Interception by PATH Environment Variable",
        tactic: "Defense Evasion",
    },
];

const GENERIC_WRITE:           u32   = 0x40000000u32;
const CREATE_ALWAYS:           u32   = 2u32;
const FILE_ATTRIBUTE_TEMPORARY: u32  = 0x00000100u32;
const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x04000000u32;
const INVALID_HANDLE_VALUE:    usize = !0usize;

dfr_fn!(
    get_environment_variable_a(
        name: *const i8,
        buf: *mut u8,
        size: u32
    ) -> u32,
    module = "kernel32.dll",
    api    = "GetEnvironmentVariableA"
);

dfr_fn!(
    create_file_a(
        name: *const i8,
        access: u32,
        share: u32,
        sec: usize,
        creation: u32,
        flags: u32,
        template: usize
    ) -> usize,
    module = "kernel32.dll",
    api    = "CreateFileA"
);

dfr_fn!(
    close_handle(h: usize) -> i32,
    module = "kernel32.dll",
    api    = "CloseHandle"
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
    // NUL-terminated "PATH" for GetEnvironmentVariableA
    let path_name: [i8; 5] = [b'P' as i8, b'A' as i8, b'T' as i8, b'H' as i8, 0i8];
    let mut path_buf = [0u8; 4096];

    let len = unsafe {
        get_environment_variable_a(
            path_name.as_ptr(),
            path_buf.as_mut_ptr(),
            4096u32,
        )
    }.map_err(|_| "env read")?;

    if len == 0 {
        return Err("PATH empty");
    }

    let path_str = core::str::from_utf8(&path_buf[..len as usize]).unwrap_or("");

    println!("PATH DLL HIJACKING CANDIDATES:");
    println!("{}", "--------------------------------------------");

    let mut writable_count: u32 = 0;
    let mut total: u32 = 0;

    // Split on ';' manually
    let mut start = 0usize;
    let bytes = path_str.as_bytes();
    loop {
        let end = bytes[start..].iter().position(|&b| b == b';')
            .map(|p| start + p)
            .unwrap_or(bytes.len());

        let entry = &path_str[start..end];
        if !entry.is_empty() && entry.len() <= 512 {
            total += 1;
            // Build test path: entry + "\\wr_test.tmp\0"
            let suffix = b"\\wr_test.tmp";
            let mut test_path = [0i8; 530];
            let entry_bytes = entry.as_bytes();
            let n = entry_bytes.len().min(517);
            for (i, &b) in entry_bytes[..n].iter().enumerate() {
                test_path[i] = b as i8;
            }
            for (i, &b) in suffix.iter().enumerate() {
                test_path[n + i] = b as i8;
            }
            // NUL already zeroed

            let h = unsafe {
                create_file_a(
                    test_path.as_ptr(),
                    GENERIC_WRITE,
                    0u32,
                    0usize,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                    0usize,
                )
            }.unwrap_or(INVALID_HANDLE_VALUE);

            if h != INVALID_HANDLE_VALUE {
                unsafe { let _ = close_handle(h); };
                println!("  [WRITABLE] {}", entry);
                writable_count += 1;
            } else {
                println!("  [readonly] {}", entry);
            }
        }

        if end >= bytes.len() {
            break;
        }
        start = end + 1;
    }

    println!("  {} of {} PATH entries are writable", writable_count, total);
    Ok(())
}
