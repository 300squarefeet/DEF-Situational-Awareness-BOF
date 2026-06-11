// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! DCOM LocalServer32 lateral movement via CoCreateInstanceEx.
//!
//! Full execution chain (deferred to Phase 6 — DCOM Invoke lateral):
//!
//!   1. CoInitializeEx(NULL, COINIT_MULTITHREADED)  [ComGuard RAII — MTA required for DCOM]
//!   2. Build COSERVERINFO for target host
//!   3. Build MULTI_QI array with IID_IDispatch
//!   4. CoCreateInstanceEx(&CLSID_MMC20_APPLICATION, NULL, CLSCTX_REMOTE_SERVER,
//!         &server_info, 1, &multi_qi)
//!      CLSID_MMC20_APPLICATION = {49B2791A-B1AE-4C90-9B8E-E860BA07F889}
//!   5. IDispatch::GetIDsOfNames(obf!("Document"))
//!   6. IDispatch::Invoke → ActiveView.ExecuteShellCommand(cmd)
//!   7. CoUninitialize  [auto via ComGuard drop]
//!
//! MITRE ATT&CK: T1021.003 (Remote Services: Distributed Component Object Model)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1021.003",
        name: "Remote Services: Distributed Component Object Model",
        tactic: "Lateral Movement",
    },
];

// CLSID_MMC20_APPLICATION = {49B2791A-B1AE-4C90-9B8E-E860BA07F889}
// Bytes in little-endian GUID field order (Data1 LE, Data2 LE, Data3 LE, Data4 verbatim)
const _CLSID_MMC20_APPLICATION: [u8; 16] = [
    0x1A, 0x79, 0xB2, 0x49, 0xAE, 0xB1, 0x90, 0x4C,
    0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89,
];

// IID_IDispatch = {00020400-0000-0000-C000-000000000046}
const _IID_IDISPATCH: [u8; 16] = [
    0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

// CoCreateInstanceEx — DFR resolved, never in .rdata as plaintext
// ppv is *mut *mut c_void (simplified — Phase 6 will use proper MULTI_QI struct)
dfr_fn!(
    co_create_instance_ex(
        rclsid:      *const u8,
        punk_outer:  *mut core::ffi::c_void,
        dw_cls_context: u32,
        pserver_info: *const core::ffi::c_void,
        dw_count:    u32,
        results:     *mut core::ffi::c_void
    ) -> i32,
    module = "ole32.dll",
    api    = "CoCreateInstanceEx"
);

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {}
        Err(e) => eprintln!("[!] {}: operation failed ({})", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // Initialize MTA COM apartment via ComGuard RAII (DCOM requires MTA)
    // Auto-CoUninitialize fires when _com drops at end of scope.
    let _com = unsafe {
        common::com::ComGuard::init_multithreaded()
    }.map_err(|_| "com init failed")?;

    // Obfuscated strings — never appear in .rdata
    obf! { let _invoke_method  = "ExecuteShellCommand"; }
    obf! { let api_name        = "CoCreateInstanceEx"; }
    obf! { let phase_note      = "Phase 6 full Invoke chain"; }

    // Default operator args
    obf! { let target     = "."; }
    obf! { let _clsid_name = "mmc20"; }
    obf! { let clsid_disp = "MMC20.Application"; }

    println!("[*] target: {}", target);
    println!("[*] clsid: {}", clsid_disp);
    println!("[*] {}: deferred ({})", api_name, phase_note);

    Ok(())
}
