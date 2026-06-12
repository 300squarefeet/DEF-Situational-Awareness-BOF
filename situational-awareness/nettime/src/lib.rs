// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1124", name: "System Time Discovery", tactic: "Discovery" },
];

const NERR_SUCCESS: u32 = 0;

// TIME_OF_DAY_INFO offsets:
//   tod_elapsedt  u32 @  0
//   tod_msecs     u32 @  4
//   tod_hours     u32 @  8
//   tod_mins      u32 @ 12
//   tod_secs      u32 @ 16
//   tod_hunds     u32 @ 20
//   tod_timezone  i32 @ 24
//   tod_tinterval u32 @ 28
//   tod_day       u32 @ 32
//   tod_month     u32 @ 36
//   tod_year      u32 @ 40
//   tod_weekday   u32 @ 44

dfr_fn!(
    net_remote_tod(
        UncServerName: *const u16,
        BufferPtr: *mut *mut u8
    ) -> u32,
    module = "netapi32.dll",
    api    = "NetRemoteTOD"
);

dfr_fn!(
    net_api_buffer_free(Buffer: *mut core::ffi::c_void) -> u32,
    module = "netapi32.dll",
    api    = "NetApiBufferFree"
);

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
    let mut buf_ptr: *mut u8 = core::ptr::null_mut();
    let ret = unsafe {
        net_remote_tod(core::ptr::null(), &mut buf_ptr)
    }.unwrap_or(1);
    if ret != NERR_SUCCESS || buf_ptr.is_null() {
        return Err("time query failed");
    }

    let hours = unsafe { core::ptr::read_unaligned(buf_ptr.add(8)  as *const u32) };
    let mins  = unsafe { core::ptr::read_unaligned(buf_ptr.add(12) as *const u32) };
    let secs  = unsafe { core::ptr::read_unaligned(buf_ptr.add(16) as *const u32) };
    let day   = unsafe { core::ptr::read_unaligned(buf_ptr.add(32) as *const u32) };
    let month = unsafe { core::ptr::read_unaligned(buf_ptr.add(36) as *const u32) };
    let year  = unsafe { core::ptr::read_unaligned(buf_ptr.add(40) as *const u32) };

    println!("Time : {:02}:{:02}:{:02}", hours, mins, secs);
    println!("Date : {:04}-{:02}-{:02}", year, month, day);

    unsafe { let _ = net_api_buffer_free(buf_ptr as *mut core::ffi::c_void); };
    Ok(())
}
