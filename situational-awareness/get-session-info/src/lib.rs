// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::string::String;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1049", name: "System Network Connections Discovery", tactic: "Discovery" },
];

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
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let id_s = String::from(parser.get_str());
    let sess_id: u32 = if id_s.is_empty() {
        0
    } else {
        id_s.parse::<u32>().map_err(|_| "invalid session id")?
    };

    println!("Session {} info:", sess_id);

    // Query string fields: WTSUserName=5, WTSClientName=10
    for &(wts_class, label) in &[(5u32, "User"), (10u32, "ClientName")] {
        let mut buf_ptr: *mut i8 = core::ptr::null_mut();
        let mut bytes: u32 = 0;
        let ok = unsafe {
            wts_query_session_information_a(
                core::ptr::null_mut(),
                sess_id,
                wts_class,
                &mut buf_ptr,
                &mut bytes,
            )
        }.unwrap_or(0);
        if ok != 0 && !buf_ptr.is_null() {
            let val = ptr_to_cstr(buf_ptr as *const u8, 256);
            println!("  {}: {}", label, val);
            unsafe { let _ = wts_free_memory(buf_ptr as *mut core::ffi::c_void); };
        }
    }

    // WTSConnectState = 8, returns a u32
    let mut state_ptr: *mut i8 = core::ptr::null_mut();
    let mut bytes2: u32 = 0;
    let ok2 = unsafe {
        wts_query_session_information_a(
            core::ptr::null_mut(),
            sess_id,
            8u32,
            &mut state_ptr,
            &mut bytes2,
        )
    }.unwrap_or(0);
    if ok2 != 0 && !state_ptr.is_null() {
        let state = unsafe { core::ptr::read_unaligned(state_ptr as *const u32) };
        println!("  State: {}", wts_state(state));
        unsafe { let _ = wts_free_memory(state_ptr as *mut core::ffi::c_void); };
    }

    Ok(())
}
