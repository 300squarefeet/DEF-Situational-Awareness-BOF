// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1049", name: "System Network Connections Discovery", tactic: "Discovery" },
];

// WTS_SESSION_INFO x64 layout:
//   SessionId:      u32 @ offset  0
//   (padding):           @ offset  4..8
//   WinStationName: *mut i8 @ offset 8
//   State:          u32 @ offset 16
const RECORD_SIZE: usize = 24;

dfr_fn!(
    wts_enumerate_sessions_a(
        hServer: *mut core::ffi::c_void,
        Reserved: u32,
        Version: u32,
        ppSessionInfo: *mut *mut u8,
        pCount: *mut u32
    ) -> i32,
    module = "wtsapi32.dll",
    api    = "WTSEnumerateSessionsA"
);

dfr_fn!(
    wts_query_session_information_a(
        hServer: *mut core::ffi::c_void,
        SessionId: u32,
        WTSInfoClass: u32,
        ppBuffer: *mut *mut i8,
        pBytesReturned: *mut u32
    ) -> i32,
    module = "wtsapi32.dll",
    api    = "WTSQuerySessionInformationA"
);

dfr_fn!(
    wts_free_memory(pMemory: *mut core::ffi::c_void) -> (),
    module = "wtsapi32.dll",
    api    = "WTSFreeMemory"
);

// ---- helpers ---------------------------------------------------------------

struct CStr { buf: [u8; 512], len: usize }
impl CStr {
    fn new() -> Self { Self { buf: [0u8; 512], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for CStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}

fn ptr_to_cstr(p: *const u8, max: usize) -> CStr {
    let mut s = CStr::new();
    if p.is_null() { return s; }
    for i in 0..max {
        let b = unsafe { core::ptr::read_volatile(p.add(i)) };
        if b == 0 { break; }
        s.push(b);
    }
    s
}

fn wts_state(s: u32) -> &'static str {
    match s {
        0 => "Active",
        1 => "Connected",
        2 => "ConnectQuery",
        3 => "Shadow",
        4 => "Disconnected",
        5 => "Idle",
        6 => "Listen",
        7 => "Reset",
        8 => "Down",
        9 => "Init",
        _ => "Unknown",
    }
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
    let mut pp_sessions: *mut u8 = core::ptr::null_mut();
    let mut count: u32 = 0;
    let ok = unsafe {
        wts_enumerate_sessions_a(
            core::ptr::null_mut(),
            0,
            1,
            &mut pp_sessions,
            &mut count,
        )
    }.unwrap_or(0);
    if ok == 0 || pp_sessions.is_null() {
        return Err("session enumeration failed");
    }

    println!("Sessions ({} total):", count);
    println!("{:<8} {:<20} {:<20} {}", "ID", "State", "WinStation", "User");

    for i in 0..count as usize {
        let base = unsafe { pp_sessions.add(i * RECORD_SIZE) };
        let sess_id = unsafe { core::ptr::read_unaligned(base as *const u32) };
        let win_name_ptr = unsafe {
            core::ptr::read_unaligned(base.add(8) as *const *const i8)
        };
        let state = unsafe { core::ptr::read_unaligned(base.add(16) as *const u32) };

        let win_name = ptr_to_cstr(win_name_ptr as *const u8, 64);
        let state_str = wts_state(state);

        let mut user_ptr: *mut i8 = core::ptr::null_mut();
        let mut bytes: u32 = 0;
        let uok = unsafe {
            wts_query_session_information_a(
                core::ptr::null_mut(),
                sess_id,
                5u32,
                &mut user_ptr,
                &mut bytes,
            )
        }.unwrap_or(0);
        if uok != 0 && !user_ptr.is_null() {
            let user = ptr_to_cstr(user_ptr as *const u8, 128);
            println!("{:<8} {:<20} {:<20} {}", sess_id, state_str, win_name, user);
            unsafe { let _ = wts_free_memory(user_ptr as *mut core::ffi::c_void); };
        } else {
            println!("{:<8} {:<20} {:<20} (unknown)", sess_id, state_str, win_name);
        }
    }

    unsafe { let _ = wts_free_memory(pp_sessions as *mut core::ffi::c_void); };
    Ok(())
}
