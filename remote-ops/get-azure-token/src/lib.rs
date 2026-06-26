// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Locate Azure/MSAL token cache files.
//! No args needed.
#![no_std]
#![cfg_attr(not(test), no_main)]

use core::ffi::c_void;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1528", name: "Steal Application Access Token", tactic: "Credential Access" },
];

const CSIDL_LOCAL_APPDATA: i32 = 0x001C;
const INVALID_HANDLE_VALUE: usize = usize::MAX;

dfr_fn!(
    sh_get_folder_path_a(
        hwnd: *mut c_void, csidl: i32, h_token: *mut c_void,
        dw_flags: u32, psz_path: *mut u8,
    ) -> i32,
    module = "shell32.dll", api = "SHGetFolderPathA"
);
dfr_fn!(
    find_first_file_a(lp: *const i8, data: *mut u8) -> *mut c_void,
    module = "kernel32.dll", api = "FindFirstFileA"
);
dfr_fn!(
    find_next_file_a(h: *mut c_void, data: *mut u8) -> i32,
    module = "kernel32.dll", api = "FindNextFileA"
);
dfr_fn!(
    find_close(h: *mut c_void) -> i32,
    module = "kernel32.dll", api = "FindClose"
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
    let _ = unsafe {
        sh_get_folder_path_a(core::ptr::null_mut(), CSIDL_LOCAL_APPDATA,
                             core::ptr::null_mut(), 0, local.as_mut_ptr())
    }.map_err(|_| "path failed")?;

    let local_len = cstr_len(&local, 260);

    let paths: &[&[u8]] = &[
        b"\\Microsoft\\.IdentityService\\*\0",
        b"\\Microsoft\\TokenBroker\\Cache\\*\0",
        b"\\Microsoft\\IdentityCache\\*\0",
        b"\\Microsoft\\MicrosoftEdge\\User\\Default\\Credentials Store\\*\0",
    ];

    println!("Azure/MSAL token cache locations:");
    for sfx in paths {
        enumerate_dir(&local[..local_len], sfx);
    }
    Ok(())
}

fn enumerate_dir(base: &[u8], suffix: &[u8]) {
    let mut path = [0u8; 512];
    let total = base.len() + suffix.len() - 1;
    if total >= 512 { return; }
    path[..base.len()].copy_from_slice(base);
    path[base.len()..base.len() + suffix.len()].copy_from_slice(suffix);

    let display_len = total.saturating_sub(2);
    rustbof::println!("  {}:", CStr::from_bytes(&path, display_len));

    let mut find_data = [0u8; 320];
    let h = unsafe { find_first_file_a(path.as_ptr() as *const i8, find_data.as_mut_ptr()) }
        .unwrap_or(core::ptr::null_mut());
    if h as usize == INVALID_HANDLE_VALUE || h.is_null() {
        rustbof::println!("    (not found)");
        return;
    }
    loop {
        let name = &find_data[44..304];
        let nlen = cstr_len(name, 260);
        if nlen > 0 && !(name[0] == b'.' && (nlen == 1 || (nlen == 2 && name[1] == b'.'))) {
            rustbof::println!("    {}", CStr::from_bytes(name, nlen));
        }
        if unsafe { find_next_file_a(h, find_data.as_mut_ptr()) }.unwrap_or(0) == 0 { break; }
    }
    unsafe { let _ = find_close(h); };
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
