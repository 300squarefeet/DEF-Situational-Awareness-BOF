// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};
use alloc::string::String;
use alloc::vec::Vec;

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
];

// BCRYPT_SHA256_ALGORITHM wide string: "SHA256\0"
const SHA256_ALG: [u16; 7] = [
    b'S' as u16, b'H' as u16, b'A' as u16,
    b'2' as u16, b'5' as u16, b'6' as u16,
    0u16,
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

// bcrypt.dll
dfr_fn!(
    bcrypt_open_algorithm_provider(
        ph_algorithm: *mut usize,
        psz_alg_id: *const u16,
        psz_implementation: *const u16,
        dw_flags: u32,
    ) -> i32,
    module = "bcrypt.dll",
    api    = "BCryptOpenAlgorithmProvider"
);

dfr_fn!(
    bcrypt_create_hash(
        h_algorithm: usize,
        ph_hash: *mut usize,
        pb_hash_object: *mut u8,
        cb_hash_object: u32,
        pb_secret: *const u8,
        cb_secret: u32,
        dw_flags: u32,
    ) -> i32,
    module = "bcrypt.dll",
    api    = "BCryptCreateHash"
);

dfr_fn!(
    bcrypt_hash_data(
        h_hash: usize,
        pb_input: *const u8,
        cb_input: u32,
        dw_flags: u32,
    ) -> i32,
    module = "bcrypt.dll",
    api    = "BCryptHashData"
);

dfr_fn!(
    bcrypt_finish_hash(
        h_hash: usize,
        pb_output: *mut u8,
        cb_output: u32,
        dw_flags: u32,
    ) -> i32,
    module = "bcrypt.dll",
    api    = "BCryptFinishHash"
);

dfr_fn!(
    bcrypt_destroy_hash(h_hash: usize) -> i32,
    module = "bcrypt.dll",
    api    = "BCryptDestroyHash"
);

dfr_fn!(
    bcrypt_close_algorithm_provider(h_algorithm: usize, dw_flags: u32) -> i32,
    module = "bcrypt.dll",
    api    = "BCryptCloseAlgorithmProvider"
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
    if path_s.is_empty() { return Err("usage: sha256 <filepath>"); }

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

    // BCryptOpenAlgorithmProvider
    let mut h_alg: usize = 0;
    let s1 = unsafe {
        bcrypt_open_algorithm_provider(&mut h_alg, SHA256_ALG.as_ptr(), core::ptr::null(), 0)
    }.unwrap_or(-1);
    if s1 != 0 {
        unsafe { let _ = close_handle(h_file); };
        return Err("algo init failed");
    }

    // BCryptCreateHash (no hash object buffer — pass null/0)
    let mut h_hash: usize = 0;
    let s2 = unsafe {
        bcrypt_create_hash(h_alg, &mut h_hash, core::ptr::null_mut(), 0, core::ptr::null(), 0, 0)
    }.unwrap_or(-1);
    if s2 != 0 {
        unsafe {
            let _ = bcrypt_close_algorithm_provider(h_alg, 0);
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
        let _ = unsafe { bcrypt_hash_data(h_hash, chunk.as_ptr(), bytes_read, 0) }.unwrap_or(-1);
    }
    unsafe { let _ = close_handle(h_file); };

    // BCryptFinishHash — SHA256 = 32 bytes
    let mut hash_buf = [0u8; 32];
    let s3 = unsafe {
        bcrypt_finish_hash(h_hash, hash_buf.as_mut_ptr(), 32, 0)
    }.unwrap_or(-1);
    unsafe {
        let _ = bcrypt_destroy_hash(h_hash);
        let _ = bcrypt_close_algorithm_provider(h_alg, 0);
    };

    if s3 != 0 { return Err("hash finish failed"); }

    println!("SHA256({}): {}", path_s.as_str(), hex_str(&hash_buf));
    Ok(())
}
