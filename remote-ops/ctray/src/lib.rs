// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Enumerate system tray child windows via Shell_TrayWnd.
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
];

const GW_CHILD:   u32 = 5;
const GW_HWNDNEXT:u32 = 2;

dfr_fn!(
    find_window_a(class: *const i8, title: *const i8) -> usize,
    module = "user32.dll",
    api    = "FindWindowA"
);

dfr_fn!(
    get_window(hwnd: usize, cmd: u32) -> usize,
    module = "user32.dll",
    api    = "GetWindow"
);

dfr_fn!(
    get_class_name_a(hwnd: usize, buf: *mut u8, max: i32) -> i32,
    module = "user32.dll",
    api    = "GetClassNameA"
);

dfr_fn!(
    get_window_text_a(hwnd: usize, buf: *mut u8, max: i32) -> i32,
    module = "user32.dll",
    api    = "GetWindowTextA"
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
    // "Shell_TrayWnd\0"
    let tray_class: [i8; 14] = [
        b'S' as i8, b'h' as i8, b'e' as i8, b'l' as i8, b'l' as i8, b'_' as i8,
        b'T' as i8, b'r' as i8, b'a' as i8, b'y' as i8, b'W' as i8, b'n' as i8,
        b'd' as i8, 0i8,
    ];

    let tray = unsafe { find_window_a(tray_class.as_ptr(), core::ptr::null()) }
        .map_err(|_| "find resolve")?;

    if tray == 0 {
        obf! { let msg = "tray window not found"; }
        println!("[!] {}", msg);
        return Ok(());
    }

    println!("Shell_TrayWnd HWND=0x{:X}", tray);

    let mut child = unsafe { get_window(tray, GW_CHILD) }
        .unwrap_or(0);

    let mut count: u32 = 0;
    while child != 0 && count < 32 {
        let mut cls_buf = [0u8; 64];
        let mut txt_buf = [0u8; 64];
        let cls_len = unsafe { get_class_name_a(child, cls_buf.as_mut_ptr(), 63) }
            .unwrap_or(0);
        let txt_len = unsafe { get_window_text_a(child, txt_buf.as_mut_ptr(), 63) }
            .unwrap_or(0);

        let cls = core::str::from_utf8(&cls_buf[..cls_len.max(0) as usize]).unwrap_or("?");
        let txt = core::str::from_utf8(&txt_buf[..txt_len.max(0) as usize]).unwrap_or("");
        println!("  HWND=0x{:X} class={} title={}", child, cls, txt);

        child = unsafe { get_window(child, GW_HWNDNEXT) }.unwrap_or(0);
        count += 1;
    }

    println!("[+] {} child window(s) listed", count);
    Ok(())
}
