// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Original C: Outflank/C2-Tool-Collection — lapsdump/
//
//! `lapsdump` — LAPS password extraction via LDAP.
//!
//! Phase 4 stub: locates the current domain controller via DsGetDcNameW
//! (netapi32.dll). Full LDAP query is deferred to Phase 5 when the shared
//! LDAP helper crate lands.
//!
//! Phase 5 LDAP filter:
//!   (&(objectClass=computer)(ms-Mcs-AdmPwd=*))
//! Attributes requested:
//!   dNSHostName, ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
//!
//! MITRE: T1555 (Credentials from Password Stores),
//!        tactic: Credential Access

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id:     "T1555",
        name:   "Credentials from Password Stores",
        tactic: "Credential Access",
    },
];

// ─── Precomputed API hash — byte literal is compile-time-const only ───────────
const HASH_DS_GET_DC_NAME_W: u32 =
    common::hash::djb2(b"DsGetDcNameW");

// ─── DFR declaration ─────────────────────────────────────────────────────────
// Note: dfr_fn! resolves by string literal at const-evaluation time.
// HASH_DS_GET_DC_NAME_W documents the hash used; no API name survives in .rdata.
dfr_fn!(
    ds_get_dc_name_w(
        computer_name: *const u16,
        domain_name:   *const u16,
        domain_guid:   *const u8,
        site_name:     *const u16,
        flags:         u32,
        dc_info:       *mut *mut DomainControllerInfo,
    ) -> u32,
    module = "netapi32.dll",
    api    = "DsGetDcNameW"
);

dfr_fn!(
    net_api_buffer_free(buffer: *mut DomainControllerInfo) -> u32,
    module = "netapi32.dll",
    api    = "NetApiBufferFree"
);

// ─── DOMAIN_CONTROLLER_INFOW layout (x64 pointer layout) ─────────────────────
// Minimal repr — we only need the first three pointer fields.
// Full struct has many more fields but we access only via pointer arithmetic.
//   +0   DomainControllerName  *u16
//   +8   DomainControllerAddress *u16
//  +16   DomainName            *u16
//  +24   DnsForestName         *u16
//  +32   Flags                 u32
//  (remaining fields not needed for this stub)
#[repr(C)]
pub struct DomainControllerInfo {
    pub dc_name:    *const u16,   // \\DC-hostname
    pub dc_address: *const u16,   // \\IP-address
    pub domain_name: *const u16,  // NetBIOS or DNS domain
    pub _rest: [usize; 4],        // padding — flags + remaining pointer fields
}

// ─── Entry point ──────────────────────────────────────────────────────────────

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(())  => {},
        Err(e)  => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // Confirm HASH_DS_GET_DC_NAME_W is used (compile-time constant in scope).
    let _ = HASH_DS_GET_DC_NAME_W;

    // ── DsGetDcNameW: locate the DC for the current domain ────────────────────
    let mut dc_info: *mut DomainControllerInfo = core::ptr::null_mut();

    let rc = unsafe {
        ds_get_dc_name_w(
            core::ptr::null(),   // computer_name  — null = local machine
            core::ptr::null(),   // domain_name    — null = current domain
            core::ptr::null(),   // domain_guid    — null = any domain
            core::ptr::null(),   // site_name      — null = any site
            0,                   // flags          — 0 = defaults
            &mut dc_info,
        )
    }.map_err(|_| "dc resolve failed")?;

    if rc != 0 || dc_info.is_null() {
        obf! { let msg = "lapsdump: not domain-joined or DC unreachable"; }
        println!("{}", msg);
        return Ok(());
    }

    // ── Extract DomainControllerName (first field, wide string) ───────────────
    let dc_name_ptr = unsafe { (*dc_info).dc_name };
    let mut dc_name_buf = [0u8; 256];
    let dc_name_len = wide_to_ascii(dc_name_ptr, &mut dc_name_buf);
    let dc_name = core::str::from_utf8(&dc_name_buf[..dc_name_len]).unwrap_or("?");

    println!("[*] lapsdump: DC found: {}", dc_name);

    // Free the NetAPI buffer
    let _ = unsafe { net_api_buffer_free(dc_info) };

    // ── Phase 5 deferred: LDAP query for LAPS passwords ──────────────────────
    // Filter : (&(objectClass=computer)(ms-Mcs-AdmPwd=*))
    // Attrs  : dNSHostName, ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
    println!("[*] lapsdump: LDAP query deferred (Phase 5 LDAP helper)");

    Ok(())
}

// ─── Wide-string to ASCII helper ─────────────────────────────────────────────
/// Copy a null-terminated wide string into `out` as ASCII/Latin-1.
/// Non-ASCII code points are replaced with `?`. Returns the number of bytes written.
fn wide_to_ascii(ptr: *const u16, out: &mut [u8]) -> usize {
    if ptr.is_null() { return 0; }
    let mut n = 0usize;
    loop {
        if n >= out.len().saturating_sub(1) { break; }
        let wc = unsafe { core::ptr::read_volatile(ptr.add(n)) };
        if wc == 0 { break; }
        out[n] = if wc < 128 { wc as u8 } else { b'?' };
        n += 1;
    }
    if n < out.len() { out[n] = 0; }
    n
}
