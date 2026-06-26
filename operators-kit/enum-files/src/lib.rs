// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Recursive file enumeration under a directory.
//! Args: <directory>
//! Limits: max 5 depth levels, max 200 files reported.
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::string::String;
use alloc::vec::Vec;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
];

const INVALID_HANDLE_VALUE:     usize = !0usize;
const FILE_ATTRIBUTE_DIRECTORY: u32   = 0x10u32;
const MAX_FILES:                usize = 200;
const MAX_DEPTH:                usize = 4; // 0-indexed, so 5 levels total (0..=4)

dfr_fn!(
    find_first_file_a(name: *const i8, data: *mut u8) -> usize,
    module = "kernel32.dll",
    api    = "FindFirstFileA"
);

dfr_fn!(
    find_next_file_a(handle: usize, data: *mut u8) -> i32,
    module = "kernel32.dll",
    api    = "FindNextFileA"
);

dfr_fn!(
    find_close(handle: usize) -> i32,
    module = "kernel32.dll",
    api    = "FindClose"
);

/// Return the length of a NUL-terminated slice (capped at `cap`).
fn strlen_capped(buf: &[u8], cap: usize) -> usize {
    buf.iter().take(cap).position(|&b| b == 0).unwrap_or(cap)
}

/// Copy a String into a NUL-terminated [i8; 1024] stack buffer for Win32 calls.
fn to_cstr_1024(s: &str) -> [i8; 1024] {
    let mut buf = [0i8; 1024];
    let n = s.len().min(1023);
    for (i, &b) in s.as_bytes()[..n].iter().enumerate() {
        buf[i] = b as i8;
    }
    buf[n] = 0;
    buf
}

/// Read dwFileAttributes (u32 LE) from offset 0 of a WIN32_FIND_DATAA buffer.
fn get_file_attrs(buf: &[u8; 320]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// Read cFileName from offset 44 of a WIN32_FIND_DATAA buffer (260 bytes).
fn get_cfilename(buf: &[u8; 320]) -> &[u8] {
    let name_bytes = &buf[44..44 + 260];
    let len = strlen_capped(name_bytes, 260);
    &name_bytes[..len]
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
    let dir_s = String::from(parser.get_str());
    let dir_arg = dir_s.as_str();
    if dir_arg.is_empty() { return Err("usage: enum-files <directory>"); }

    // Queue of (path, depth)
    let mut queue: Vec<(String, usize)> = Vec::new();
    queue.push((String::from(dir_arg), 0));

    let mut file_count: usize = 0;

    println!("{}", obf!("[*] Enumerating files..."));

    while !queue.is_empty() && file_count < MAX_FILES {
        let (dir_path, depth) = queue.remove(0);

        // Build search pattern: dir_path + "\\*"
        let mut search = String::from(dir_path.as_str());
        search.push_str("\\*");

        let search_cstr = to_cstr_1024(search.as_str());
        let mut find_data = [0u8; 320];

        let h = unsafe {
            find_first_file_a(search_cstr.as_ptr(), find_data.as_mut_ptr())
        }.unwrap_or(INVALID_HANDLE_VALUE);

        if h == INVALID_HANDLE_VALUE || h == 0 {
            continue;
        }

        loop {
            let attrs = get_file_attrs(&find_data);
            let name_bytes = {
                let nb = get_cfilename(&find_data);
                let mut owned = [0u8; 260];
                let len = nb.len().min(260);
                owned[..len].copy_from_slice(&nb[..len]);
                (owned, len)
            };

            let name_slice = &name_bytes.0[..name_bytes.1];

            // Skip "." and ".."
            let is_dot = name_slice == b"." || name_slice == b"..";

            if !is_dot {
                let mut full_path = String::from(dir_path.as_str());
                full_path.push('\\');
                if let Ok(name_str) = core::str::from_utf8(name_slice) {
                    full_path.push_str(name_str);
                }

                let is_dir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;

                if is_dir {
                    if depth < MAX_DEPTH {
                        queue.push((full_path, depth + 1));
                    }
                } else {
                    println!("  {}", full_path.as_str());
                    file_count += 1;
                    if file_count >= MAX_FILES {
                        unsafe { let _ = find_close(h); };
                        println!("{}", obf!("[!] File limit reached (200)."));
                        println!("Total: {} file(s) found.", file_count);
                        return Ok(());
                    }
                }
            }

            find_data = [0u8; 320];
            let next = unsafe {
                find_next_file_a(h, find_data.as_mut_ptr())
            }.unwrap_or(0);
            if next == 0 {
                break;
            }
        }

        unsafe { let _ = find_close(h); };
    }

    println!("Total: {} file(s) found.", file_count);
    Ok(())
}
