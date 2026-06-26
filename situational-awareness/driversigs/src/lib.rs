// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
#![no_std]
#![cfg_attr(not(test), no_main)]


use alloc::vec::Vec;

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1518.001", name: "Security Software Discovery", tactic: "Discovery" },
];

// WinVerifyTrust GUID = {00aac56b-cd44-11d0-8cc2-00c04fc295ee}
const WINTRUST_ACTION_GENERIC_VERIFY: [u8; 16] = [
    0x6b, 0xc5, 0xaa, 0x00, 0x44, 0xcd, 0xd0, 0x11,
    0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee,
];

const ERROR_SUCCESS: u32 = 0;

dfr_fn!(
    win_verify_trust(
        hwnd: usize,
        action: *const u8,
        data: *mut WinTrustData,
    ) -> i32,
    module = "wintrust.dll",
    api    = "WinVerifyTrust"
);

dfr_fn!(
    nt_query_system_information_raw(
        info_class: u32,
        buf: *mut u8,
        len: u32,
        ret: *mut u32,
    ) -> i32,
    module = "ntdll.dll",
    api    = "NtQuerySystemInformation"
);

// SystemModuleInformation = 11
const SystemModuleInformation: u32 = 11;
const STATUS_SUCCESS: i32 = 0;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;

#[repr(C)]
struct WinTrustFileInfo {
    cb_struct: u32,
    pc_wstr_file_path: *const u16,
    h_file: usize,
    p_last_err: *mut u8,
}

#[repr(C)]
struct WinTrustData {
    cb_struct: u32,
    p_policy_callback_data: *mut u8,
    p_sip_client_data: *mut u8,
    dw_ui_choice: u32,
    fdw_revocation_checks: u32,
    dw_union_choice: u32,
    p_file: *mut WinTrustFileInfo,
    dw_state_action: u32,
    h_wvt_state_data: usize,
    p_wstr_action: *mut u16,
    dw_provider_flags: u32,
    p_auth_and_install: *mut u8,
    dw_ui_context: u32,
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
    // Enumerate loaded kernel modules via NtQuerySystemInformation(SystemModuleInformation)
    let mut size: u32 = 65536;
    let module_buf: Vec<u8>;

    loop {
        let mut v: Vec<u8> = alloc::vec![0u8; size as usize];
        let mut ret: u32 = 0;
        let rc = unsafe {
            nt_query_system_information_raw(SystemModuleInformation, v.as_mut_ptr(), size, &mut ret)
        }.map_err(|_| "resolve failed")?;

        if rc == STATUS_SUCCESS {
            module_buf = v;
            break;
        } else if rc == STATUS_INFO_LENGTH_MISMATCH {
            size = ret.max(size * 2);
            continue;
        } else {
            return Err("sysq failed");
        }
    }

    // RTL_PROCESS_MODULES:
    // +0 NumberOfModules u32
    // +8 Modules[0] RTL_PROCESS_MODULE_INFORMATION (296 bytes each on x64):
    //   +0  Section (PVOID)
    //   +8  MappedBase
    //   +16 ImageBase
    //   +24 ImageSize u32
    //   +28 Flags u32
    //   +32 LoadOrderIndex u16
    //   +34 InitOrderIndex u16
    //   +36 LoadCount u16
    //   +38 OffsetToFileName u16
    //   +40 FullPathName [u8; 256]
    const MODULE_INFO_SIZE: usize = 296;
    let num = unsafe { core::ptr::read_unaligned(module_buf.as_ptr() as *const u32) } as usize;
    let base = unsafe { module_buf.as_ptr().add(8) };

    println!("DRIVER SIGNATURE CHECK ({} modules):", num);
    println!("{:<8} {:<12} {}", "Status", "Flags", "Path");
    println!("{}", "--------------------------------------------");

    for i in 0..num.min(256) {
        let entry = unsafe { base.add(i * MODULE_INFO_SIZE) };
        let flags = unsafe { core::ptr::read_unaligned(entry.add(28) as *const u32) };
        let path_ptr = unsafe { entry.add(40) };
        let path = bytes_to_str(path_ptr, 256);

        // Only check *.sys files
        let path_bytes = &path.buf[..path.len];
        let is_sys = path_bytes.windows(4).any(|w| w == b".sys" || w == b".SYS");
        if !is_sys { continue; }

        // Build wide path for WinVerifyTrust
        let mut wide_path = [0u16; 260];
        let path_len = path.len.min(259);
        for (j, &b) in path_bytes.iter().take(path_len).enumerate() {
            wide_path[j] = b as u16;
        }

        let mut file_info = WinTrustFileInfo {
            cb_struct: core::mem::size_of::<WinTrustFileInfo>() as u32,
            pc_wstr_file_path: wide_path.as_ptr(),
            h_file: usize::MAX, // INVALID_HANDLE_VALUE
            p_last_err: core::ptr::null_mut(),
        };

        let mut trust_data = WinTrustData {
            cb_struct: core::mem::size_of::<WinTrustData>() as u32,
            p_policy_callback_data: core::ptr::null_mut(),
            p_sip_client_data: core::ptr::null_mut(),
            dw_ui_choice: 2,      // WTD_UI_NONE
            fdw_revocation_checks: 0, // WTD_REVOKE_NONE
            dw_union_choice: 1,   // WTD_CHOICE_FILE
            p_file: &mut file_info,
            dw_state_action: 1,   // WTD_STATEACTION_VERIFY
            h_wvt_state_data: 0,
            p_wstr_action: core::ptr::null_mut(),
            dw_provider_flags: 0,
            p_auth_and_install: core::ptr::null_mut(),
            dw_ui_context: 0,
        };

        let sig_result = unsafe {
            win_verify_trust(
                0, // INVALID_HANDLE_VALUE for no window
                WINTRUST_ACTION_GENERIC_VERIFY.as_ptr(),
                &mut trust_data,
            )
        };

        let status = match sig_result.map(|r| r as u32) {
            Ok(0) => "SIGNED",
            _ => "UNSIGNED",
        };
        println!("{:<8} {:<12} {}", status, flags, path);
    }
    Ok(())
}

fn bytes_to_str(ptr: *const u8, max: usize) -> ByteStr {
    let mut s = ByteStr::new();
    if ptr.is_null() { return s; }
    for i in 0..max {
        let b = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if b == 0 { break; }
        s.push(b);
    }
    s
}

struct ByteStr { buf: [u8; 256], pub len: usize }
impl ByteStr {
    fn new() -> Self { Self { buf: [0u8; 256], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for ByteStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
