// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Check for UxSubclassInfo/CC32SubclassInfo window properties (AV/EDR hooking indicator).
//! No args needed.
#![no_std]
#![cfg_attr(not(test), no_main)]

use core::ffi::c_void;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1055", name: "Process Injection", tactic: "Defense Evasion" },
];

dfr_fn!(
    find_window_a(cls: *const i8, wnd: *const i8) -> *mut c_void,
    module = "user32.dll", api = "FindWindowA"
);
dfr_fn!(
    find_window_ex_a(
        parent: *mut c_void, child: *mut c_void, cls: *const i8, wnd: *const i8,
    ) -> *mut c_void,
    module = "user32.dll", api = "FindWindowExA"
);
dfr_fn!(
    get_prop_a(hwnd: *mut c_void, str: *const i8) -> *mut c_void,
    module = "user32.dll", api = "GetPropA"
);
dfr_fn!(
    get_class_name_a(hwnd: *mut c_void, buf: *mut u8, n: i32) -> i32,
    module = "user32.dll", api = "GetClassNameA"
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
    let ux_prop  = b"UxSubclassInfo\0";
    let cc_prop  = b"CC32SubclassInfo\0";

    println!("Checking window subclass hooks:");

    // Check Shell_TrayWnd (taskbar)
    let tray_cls = b"Shell_TrayWnd\0";
    let h_tray = unsafe {
        find_window_a(tray_cls.as_ptr() as *const i8, core::ptr::null())
    }.map_err(|_| "find failed")?;

    if !h_tray.is_null() {
        check_window(h_tray, b"Shell_TrayWnd\0", ux_prop, cc_prop);
        // Check children
        let mut child: *mut c_void = core::ptr::null_mut();
        for _ in 0..16 {
            let c = unsafe {
                find_window_ex_a(h_tray, child, core::ptr::null(), core::ptr::null())
            }.unwrap_or(core::ptr::null_mut());
            if c.is_null() { break; }
            check_window(c, b"<child>\0", ux_prop, cc_prop);
            child = c;
        }
    }

    // Check Desktop window
    let desk_cls = b"Progman\0";
    let h_desk = unsafe {
        find_window_a(desk_cls.as_ptr() as *const i8, core::ptr::null())
    }.unwrap_or(core::ptr::null_mut());
    if !h_desk.is_null() {
        check_window(h_desk, desk_cls, ux_prop, cc_prop);
    }

    println!("Done.");
    Ok(())
}

fn check_window(hwnd: *mut c_void, label: &[u8], ux_prop: &[u8], cc_prop: &[u8]) {
    let mut cls_buf = [0u8; 64];
    let _ = unsafe { get_class_name_a(hwnd, cls_buf.as_mut_ptr(), 64) };
    let clen = cls_buf.iter().position(|&b| b == 0).unwrap_or(64);
    let cls_s = core::str::from_utf8(&cls_buf[..clen]).unwrap_or("?");

    let llen = label.iter().position(|&b| b == 0).unwrap_or(label.len());
    let label_s = core::str::from_utf8(&label[..llen]).unwrap_or("?");

    let ux = unsafe { get_prop_a(hwnd, ux_prop.as_ptr() as *const i8) }.unwrap_or(core::ptr::null_mut());
    let cc = unsafe { get_prop_a(hwnd, cc_prop.as_ptr() as *const i8) }.unwrap_or(core::ptr::null_mut());

    if !ux.is_null() || !cc.is_null() {
        rustbof::println!("[!] HOOKED: {} (class={}) UxSubclass={:p} CC32={:p}",
                          label_s, cls_s, ux, cc);
    } else {
        rustbof::println!("[-] clean: {} (class={})", label_s, cls_s);
    }
}
