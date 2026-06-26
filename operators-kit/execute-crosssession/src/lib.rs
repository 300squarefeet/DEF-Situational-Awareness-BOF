// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Cross-session COM execution via IHxHelpPaneServer.
//!
//! Full execution chain (deferred to Phase 6 — IHxHelpPaneServer lateral):
//!
//!   1. CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)  [ComGuard RAII]
//!   2. Enumerate sessions via WTSEnumerateSessions / WTSQuerySessionInformation
//!   3. CoCreateInstance(&CLSID_STANDARD_ACTIVATOR, NULL, CLSCTX_LOCAL_SERVER,
//!         &IID_IStandardActivator, &pActivator)
//!   4. pActivator->SetActivationInfo(session_id, ...)
//!   5. CoCreateInstance(&CLSID_HxHelpPaneServer, ..., &pHelpPane)
//!      CLSID_HxHelpPaneServer = {8cec58ae-07a1-11d9-b15e-000d56bfe6ee}
//!   6. pHelpPane->Execute(cmd_wide)    [IHxHelpPaneServer::Execute]
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

// CLSID_STANDARD_ACTIVATOR = {7B7F0AE0-FB78-11D0-A29A-00A0C922E6EC}
// Bytes in little-endian GUID field order (Data1 LE, Data2 LE, Data3 LE, Data4 verbatim)
const _CLSID_STANDARD_ACTIVATOR: [u8; 16] = [
    0xE0, 0x0A, 0x7F, 0x7B, 0x78, 0xFB, 0xD0, 0x11,
    0xA2, 0x9A, 0x00, 0xA0, 0xC9, 0x22, 0xE6, 0xEC,
];

// CoCreateInstance — DFR resolved, never in .rdata as plaintext
dfr_fn!(
    co_create_instance(
        rclsid:  *const u8,
        punk_outer: *mut core::ffi::c_void,
        dw_cls_context: u32,
        riid:    *const u8,
        ppv:     *mut *mut core::ffi::c_void
    ) -> i32,
    module = "ole32.dll",
    api    = "CoCreateInstance"
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
    // Initialize STA COM apartment via ComGuard RAII (auto-CoUninitialize on drop)
    let _com = unsafe {
        common::com::ComGuard::init_apartment()
    }.map_err(|_| "com init failed")?;

    // Obfuscated strings — never appear in .rdata
    obf! { let _iface_name  = "IHxHelpPaneServer"; }
    obf! { let phase_note   = "Phase 6 IHxHelpPaneServer chain"; }

    // Default operator args
    let session: u32 = 1;
    obf! { let cmd = ""; }

    println!("[*] target session: {}", session);
    println!("[*] cmd: {}", cmd);
    println!("[*] cross-session execution: deferred ({})", phase_note);

    Ok(())
}
