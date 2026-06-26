// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};
use alloc::string::String;
use alloc::vec::Vec;

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
];

// kernel32.dll
dfr_fn!(
    create_file_a(
        lp_file_name: *const i8,
        dw_desired_access: u32,
        dw_share_mode: u32,
        lp_security_attributes: *mut core::ffi::c_void,
        dw_creation_disposition: u32,
        dw_flags_and_attributes: u32,
        h_template_file: *mut core::ffi::c_void,
    ) -> *mut core::ffi::c_void,
    module = "kernel32.dll",
    api    = "CreateFileA"
);

dfr_fn!(
    read_file(
        h_file: *mut core::ffi::c_void,
        lp_buffer: *mut u8,
        n_number_of_bytes_to_read: u32,
        lp_number_of_bytes_read: *mut u32,
        lp_overlapped: *mut core::ffi::c_void,
    ) -> i32,
    module = "kernel32.dll",
    api    = "ReadFile"
);

dfr_fn!(
    close_handle(h_object: *mut core::ffi::c_void) -> i32,
    module = "kernel32.dll",
    api    = "CloseHandle"
);

// advapi32.dll
dfr_fn!(
    crypt_acquire_context_a(
        ph_prov: *mut usize,
        psz_container: *const i8,
        psz_provider: *const i8,
        dw_prov_type: u32,
        dw_flags: u32,
    ) -> i32,
    module = "advapi32.dll",
    api    = "CryptAcquireContextA"
);

dfr_fn!(
    crypt_create_hash(
        h_prov: usize,
        algid: u32,
        h_key: usize,
        dw_flags: u32,
        ph_hash: *mut usize,
    ) -> i32,
    module = "advapi32.dll",
    api    = "CryptCreateHash"
);

dfr_fn!(
    crypt_hash_data(
        h_hash: usize,
        pb_data: *const u8,
        dw_data_len: u32,
        dw_flags: u32,
    ) -> i32,
    module = "advapi32.dll",
    api    = "CryptHashData"
);

dfr_fn!(
    crypt_get_hash_param(
        h_hash: usize,
        dw_param: u32,
        pb_data: *mut u8,
        pdw_data_len: *mut u32,
        dw_flags: u32,
    ) -> i32,
    module = "advapi32.dll",
    api    = "CryptGetHashParam"
);

dfr_fn!(
    crypt_destroy_hash(h_hash: usize) -> i32,
    module = "advapi32.dll",
    api    = "CryptDestroyHash"
);

dfr_fn!(
    crypt_release_context(h_prov: usize, dw_flags: u32) -> i32,
    module = "advapi32.dll",
    api    = "CryptReleaseContext"
);

struct HexStr { buf: [u8; 64], len: usize }
impl HexStr {
    fn new() -> Self { Self { buf: [0u8; 64], len: 0 } }
    fn push(&mut self, b: u8) { if self.len < 64 { self.buf[self.len] = b; self.len += 1; } }
}
impl core::fmt::Display for HexStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}

fn hex_str(bytes: &[u8]) -> HexStr {
    let mut s = HexStr::new();
    for &b in bytes {
        let hi = b >> 4;
        let lo = b & 0xF;
        s.push(if hi < 10 { b'0' + hi } else { b'a' + hi - 10 });
        s.push(if lo < 10 { b'0' + lo } else { b'a' + lo - 10 });
    }
    s
}

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
    let path_s = String::from(parser.get_str());
    if path_s.is_empty() { return Err("usage: sha1 <filepath>"); }

    let mut path_buf = [0u8; 512];
    let plen = path_s.len().min(511);
    path_buf[..plen].copy_from_slice(&path_s.as_bytes()[..plen]);

    let h_file = unsafe {
        create_file_a(
            path_buf.as_ptr() as *const i8,
            0x80000000u32, 1u32, core::ptr::null_mut(),
            3u32, 0x80u32, core::ptr::null_mut(),
        )
    }.map_err(|_| "open failed")?;

    if h_file == usize::MAX as *mut core::ffi::c_void || h_file.is_null() {
        return Err("open failed");
    }

    // CryptAcquireContext — PROV_RSA_FULL=1, CRYPT_VERIFYCONTEXT=0xF0000000
    let mut h_prov: usize = 0;
    let ok = unsafe {
        crypt_acquire_context_a(
            &mut h_prov, core::ptr::null(), core::ptr::null(),
            1u32, 0xF0000000u32,
        )
    }.unwrap_or(0);
    if ok == 0 {
        unsafe { let _ = close_handle(h_file); };
        return Err("crypto init failed");
    }

    // CryptCreateHash — CALG_SHA1 = 0x8004
    let mut h_hash: usize = 0;
    let ok2 = unsafe { crypt_create_hash(h_prov, 0x8004u32, 0, 0, &mut h_hash) }.unwrap_or(0);
    if ok2 == 0 {
        unsafe {
            let _ = crypt_release_context(h_prov, 0);
            let _ = close_handle(h_file);
        };
        return Err("hash init failed");
    }

    // Read file in 4096-byte chunks and hash
    let mut chunk: Vec<u8> = alloc::vec![0u8; 4096];
    loop {
        let mut bytes_read: u32 = 0;
        let r = unsafe {
            read_file(h_file, chunk.as_mut_ptr(), chunk.len() as u32, &mut bytes_read, core::ptr::null_mut())
        }.unwrap_or(0);
        if r == 0 || bytes_read == 0 { break; }
        let _ = unsafe { crypt_hash_data(h_hash, chunk.as_ptr(), bytes_read, 0) }.unwrap_or(0);
    }
    unsafe { let _ = close_handle(h_file); };

    // CryptGetHashParam — HP_HASHVAL = 0x0002, SHA1 = 20 bytes
    let mut hash_buf = [0u8; 20];
    let mut hash_len: u32 = 20;
    let ok3 = unsafe {
        crypt_get_hash_param(h_hash, 0x0002u32, hash_buf.as_mut_ptr(), &mut hash_len, 0)
    }.unwrap_or(0);
    unsafe {
        let _ = crypt_destroy_hash(h_hash);
        let _ = crypt_release_context(h_prov, 0);
    };

    if ok3 == 0 { return Err("hash get failed"); }

    println!("SHA1({}): {}", path_s.as_str(), hex_str(&hash_buf[..hash_len as usize]));
    Ok(())
}
