// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
#![no_std]
#![cfg_attr(not(test), no_main)]


use alloc::vec::Vec;

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1010", name: "Application Window Discovery", tactic: "Discovery" },
];

dfr_fn!(
    enum_windows(
        callback: unsafe extern "system" fn(hwnd: usize, lparam: isize) -> i32,
        lparam: isize,
    ) -> i32,
    module = "user32.dll",
    api    = "EnumWindows"
);

dfr_fn!(
    get_window_text_a(hwnd: usize, buf: *mut i8, max_count: i32) -> i32,
    module = "user32.dll",
    api    = "GetWindowTextA"
);

dfr_fn!(
    is_window_visible(hwnd: usize) -> i32,
    module = "user32.dll",
    api    = "IsWindowVisible"
);

dfr_fn!(
    get_window_thread_process_id(hwnd: usize, pid: *mut u32) -> u32,
    module = "user32.dll",
    api    = "GetWindowThreadProcessId"
);

// Callback data: store titles as NUL-separated entries in a shared Vec
// We use a global static for the callback since we can't capture in fn pointers.
// Simple approach: write to a beacon-output buffer via a static
static mut RESULT_VEC: *mut Vec<u8> = core::ptr::null_mut();

unsafe extern "system" fn enum_wnd_callback(hwnd: usize, _lparam: isize) -> i32 {
    // Only enumerate visible windows
    if let Ok(v) = is_window_visible(hwnd) {
        if v == 0 { return 1; }
    }
    let mut title = [0i8; 256];
    let len = if let Ok(n) = get_window_text_a(hwnd, title.as_mut_ptr(), 255) { n } else { 0 };
    if len > 0 {
        let mut pid: u32 = 0;
        let _ = get_window_thread_process_id(hwnd, &mut pid);
        // Print directly since we can't easily use the vec from an extern fn
        // Re-use rustbof println — safe to call from callback context
        let title_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(title.as_ptr() as *const u8, len as usize)
        };
        let s = core::str::from_utf8(title_bytes).unwrap_or("?");
        rustbof::println!("  [{:>6}]  {}", pid, s);
    }
    1 // continue enumeration
}

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    println!("WINDOWS:");
    println!("{}", "--------------------------------------------");
    println!("{:<10}  {}", "PID", "Title");
    let _ = unsafe { enum_windows(enum_wnd_callback, 0) }
        .map_err(|_| "EnumWindows resolve failed")?;
    Ok(())
}
