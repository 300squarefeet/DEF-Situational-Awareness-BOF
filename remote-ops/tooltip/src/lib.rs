// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Enumerate tooltip control windows (tooltips_class32).
//! No args needed.
#![no_std]
#![cfg_attr(not(test), no_main)]

use core::ffi::c_void;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1010", name: "Application Window Discovery", tactic: "Discovery" },
];

dfr_fn!(
    find_window_ex_a(
        parent: *mut c_void, child: *mut c_void,
        cls: *const i8, wnd: *const i8,
    ) -> *mut c_void,
    module = "user32.dll", api = "FindWindowExA"
);
dfr_fn!(
    get_window_text_a(hwnd: *mut c_void, buf: *mut u8, n: i32) -> i32,
    module = "user32.dll", api = "GetWindowTextA"
);
dfr_fn!(
    get_window_thread_process_id(hwnd: *mut c_void, pid: *mut u32) -> u32,
    module = "user32.dll", api = "GetWindowThreadProcessId"
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
    let cls = b"tooltips_class32\0";
    println!("Enumerating tooltips_class32 windows:");
    let mut prev: *mut c_void = core::ptr::null_mut();
    let mut count = 0u32;
    loop {
        let hwnd = unsafe {
            find_window_ex_a(core::ptr::null_mut(), prev, cls.as_ptr() as *const i8, core::ptr::null())
        }.map_err(|_| "enum failed")?;
        if hwnd.is_null() { break; }
        let mut title = [0u8; 128];
        let tlen = unsafe { get_window_text_a(hwnd, title.as_mut_ptr(), 128) }.unwrap_or(0);
        let mut pid: u32 = 0;
        let tid = unsafe { get_window_thread_process_id(hwnd, &mut pid) }.unwrap_or(0);
        let tstr = if tlen > 0 {
            core::str::from_utf8(&title[..tlen as usize]).unwrap_or("?")
        } else { "(no title)" };
        println!("  HWND={:p} PID={} TID={} title=\"{}\"", hwnd, pid, tid, tstr);
        prev = hwnd;
        count += 1;
        if count >= 32 { println!("  (truncated at 32)"); break; }
    }
    println!("{} tooltip windows found", count);
    Ok(())
}
