// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Print file ACLs as SDDL string via GetNamedSecurityInfo.
//! Args: <filepath>
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::string::String;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
];

const SE_FILE_OBJECT: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
const OWNER_SECURITY_INFORMATION: u32 = 0x00000001;
const SDDL_REVISION_1: u32 = 1;

dfr_fn!(
    get_named_security_info_a(
        p_object_name: *const i8,
        object_type: u32,
        security_info: u32,
        pp_sid_owner: *mut *mut core::ffi::c_void,
        pp_sid_group: *mut *mut core::ffi::c_void,
        pp_dacl: *mut *mut core::ffi::c_void,
        pp_sacl: *mut *mut core::ffi::c_void,
        pp_security_descriptor: *mut *mut core::ffi::c_void,
    ) -> u32,
    module = "advapi32.dll",
    api    = "GetNamedSecurityInfoA"
);

dfr_fn!(
    convert_security_descriptor_to_string_security_descriptor_a(
        p_security_descriptor: *mut core::ffi::c_void,
        requested_string_sd_revision: u32,
        security_information: u32,
        string_security_descriptor: *mut *mut i8,
        string_security_descriptor_len: *mut u32,
    ) -> i32,
    module = "advapi32.dll",
    api    = "ConvertSecurityDescriptorToStringSecurityDescriptorA"
);

dfr_fn!(
    local_free(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void,
    module = "kernel32.dll",
    api    = "LocalFree"
);

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
    if path_s.is_empty() {
        return Err("usage: cacls <filepath>");
    }

    let mut path_buf = [0u8; 512];
    let plen = path_s.len().min(511);
    path_buf[..plen].copy_from_slice(&path_s.as_bytes()[..plen]);

    let mut p_sd: *mut core::ffi::c_void = core::ptr::null_mut();
    let rc = unsafe {
        get_named_security_info_a(
            path_buf.as_ptr() as *const i8,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut p_sd,
        )
    }.map_err(|_| "query failed")?;

    if rc != 0 {
        return Err("query failed");
    }

    let mut p_sddl: *mut i8 = core::ptr::null_mut();
    let mut sddl_len: u32 = 0;
    let ok = unsafe {
        convert_security_descriptor_to_string_security_descriptor_a(
            p_sd,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut p_sddl,
            &mut sddl_len,
        )
    }.map_err(|_| "convert failed")?;

    if ok == 0 {
        unsafe { let _ = local_free(p_sd); };
        return Err("convert failed");
    }

    // Print the SDDL string
    let sddl = if p_sddl.is_null() {
        ""
    } else {
        unsafe {
            let sl = sddl_len as usize;
            core::str::from_utf8_unchecked(
                core::slice::from_raw_parts(p_sddl as *const u8, sl)
            )
        }
    };

    println!("File  : {}", path_s.as_str());
    println!("SDDL  : {}", sddl);

    unsafe {
        if !p_sddl.is_null() { let _ = local_free(p_sddl as *mut core::ffi::c_void); }
        let _ = local_free(p_sd);
    };
    Ok(())
}
