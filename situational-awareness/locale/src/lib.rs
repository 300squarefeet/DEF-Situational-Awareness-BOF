// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1614", name: "System Location Discovery", tactic: "Discovery" },
];

dfr_fn!(
    get_system_default_locale_name(
        lpLocaleName: *mut u16,
        cchLocaleName: i32
    ) -> i32,
    module = "kernel32.dll",
    api    = "GetSystemDefaultLocaleName"
);

dfr_fn!(
    get_time_zone_information(lpTimeZoneInformation: *mut u8) -> u32,
    module = "kernel32.dll",
    api    = "GetTimeZoneInformation"
);

dfr_fn!(
    get_acp() -> u32,
    module = "kernel32.dll",
    api    = "GetACP"
);

// ---- helpers ---------------------------------------------------------------

struct WStr { buf: [u8; 128], len: usize }
impl WStr {
    fn new() -> Self { Self { buf: [0u8; 128], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for WStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}

fn wide_to_str(ptr: *const u16, max: usize) -> WStr {
    let mut s = WStr::new();
    if ptr.is_null() { return s; }
    for i in 0..max {
        let wc = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if wc == 0 { break; }
        s.push(if wc < 128 { wc as u8 } else { b'?' });
    }
    s
}

// ---- entry -----------------------------------------------------------------

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // Locale name
    let mut locale_buf = [0u16; 85];
    let _ = unsafe {
        get_system_default_locale_name(locale_buf.as_mut_ptr(), locale_buf.len() as i32)
    }.unwrap_or(0);
    let locale = wide_to_str(locale_buf.as_ptr(), 84);
    println!("Locale  : {}", locale);

    // Timezone — TIME_ZONE_INFORMATION = 172 bytes
    // StandardName is [u16;32] at offset 4
    let mut tz_buf = [0u8; 172];
    let _ = unsafe {
        get_time_zone_information(tz_buf.as_mut_ptr())
    }.unwrap_or(0);
    let tz_name_ptr = unsafe { tz_buf.as_ptr().add(4) as *const u16 };
    let tz_name = wide_to_str(tz_name_ptr, 32);
    println!("Timezone: {}", tz_name);

    // Active code page
    let cp = unsafe { get_acp() }.unwrap_or(0);
    println!("CodePage: {}", cp);

    Ok(())
}
