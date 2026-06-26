// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Directory listing via FindFirstFileA/FindNextFileA.
//! Args: <path>
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::string::String;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
];

const INVALID_HANDLE_VALUE: usize = !0usize;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

// WIN32_FIND_DATAA = 320 bytes
#[repr(C)]
struct Win32FindDataA {
    dw_file_attributes:    u32,
    ft_creation_time:      [u32; 2],
    ft_last_access_time:   [u32; 2],
    ft_last_write_time:    [u32; 2],
    n_file_size_high:      u32,
    n_file_size_low:       u32,
    dw_reserved0:          u32,
    dw_reserved1:          u32,
    c_file_name:           [u8; 260],
    c_alternate_file_name: [u8; 14],
    _pad:                  [u8; 2],
}

dfr_fn!(
    find_first_file_a(
        lp_file_name: *const i8,
        lp_find_file_data: *mut Win32FindDataA,
    ) -> usize,
    module = "kernel32.dll",
    api    = "FindFirstFileA"
);

dfr_fn!(
    find_next_file_a(
        h_find_file: usize,
        lp_find_file_data: *mut Win32FindDataA,
    ) -> i32,
    module = "kernel32.dll",
    api    = "FindNextFileA"
);

dfr_fn!(
    find_close(h_find_file: usize) -> i32,
    module = "kernel32.dll",
    api    = "FindClose"
);

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
    let path_s = String::from(parser.get_str());
    if path_s.is_empty() {
        return Err("usage: dir <path>");
    }

    // Build search pattern: append \* if needed
    let mut search_buf = [0u8; 520];
    let plen = path_s.len().min(516);
    search_buf[..plen].copy_from_slice(&path_s.as_bytes()[..plen]);
    // append \*
    if search_buf[plen - 1] != b'\\' {
        search_buf[plen] = b'\\';
        search_buf[plen + 1] = b'*';
    } else {
        search_buf[plen] = b'*';
    }

    let mut find_data = Win32FindDataA {
        dw_file_attributes: 0,
        ft_creation_time: [0; 2],
        ft_last_access_time: [0; 2],
        ft_last_write_time: [0; 2],
        n_file_size_high: 0,
        n_file_size_low: 0,
        dw_reserved0: 0,
        dw_reserved1: 0,
        c_file_name: [0u8; 260],
        c_alternate_file_name: [0u8; 14],
        _pad: [0u8; 2],
    };

    let handle = unsafe {
        find_first_file_a(search_buf.as_ptr() as *const i8, &mut find_data)
    }.map_err(|_| "search failed")?;

    if handle == INVALID_HANDLE_VALUE {
        return Err("search failed");
    }

    println!("Directory listing: {}", path_s.as_str());
    println!("{:<8} {:>12}  {}", "Type", "Size", "Name");
    println!("{}", "---------------------------------------------------");

    let mut count = 0u32;
    loop {
        let is_dir = (find_data.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        let size = ((find_data.n_file_size_high as u64) << 32) | (find_data.n_file_size_low as u64);
        let fname = cstr_to_str(&find_data.c_file_name);
        let type_str = if is_dir { "<DIR>" } else { "     " };
        println!("{:<8} {:>12}  {}", type_str, size, fname);
        count += 1;

        let more = unsafe {
            find_next_file_a(handle, &mut find_data)
        }.unwrap_or(0);
        if more == 0 { break; }
    }

    unsafe { let _ = find_close(handle); };
    println!("\n[+] {} entries", count);
    Ok(())
}

fn cstr_to_str(buf: &[u8]) -> &str {
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..nul]).unwrap_or("?")
}
