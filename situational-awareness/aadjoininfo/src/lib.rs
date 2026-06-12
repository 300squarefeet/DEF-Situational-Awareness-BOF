// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Azure AD join status via NetGetAadJoinInformation.
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1518", name: "Software Discovery", tactic: "Discovery" },
];

// DSREG_JOIN_TYPE: 0=Unknown, 1=DeviceJoined, 2=WorkplaceJoined
#[repr(C)]
struct DsregJoinInfo {
    join_type: u32,
    p_join_certificate: *mut core::ffi::c_void,
    p_device_id: *mut u16,
    p_id_idp_domain: *mut u16,
    p_tenant_id: *mut u16,
    p_join_user_email: *mut u16,
    p_mdm_enrollment_url: *mut u16,
    p_mdm_terms_of_use_url: *mut u16,
    p_mdm_compliance_url: *mut u16,
    p_user_setting_sync_url: *mut u16,
    p_user_info: *mut core::ffi::c_void,
}

dfr_fn!(
    net_get_aad_join_information(
        pcn_entry: *const u16,
        pp_join_info: *mut *mut DsregJoinInfo,
    ) -> i32,
    module = "netapi32.dll",
    api    = "NetGetAadJoinInformation"
);

dfr_fn!(
    net_free_aad_join_information(p_join_info: *mut DsregJoinInfo) -> (),
    module = "netapi32.dll",
    api    = "NetFreeAadJoinInformation"
);

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    let mut p_info: *mut DsregJoinInfo = core::ptr::null_mut();
    let hr = unsafe { net_get_aad_join_information(core::ptr::null(), &mut p_info) }
        .map_err(|_| "query failed")?;

    if hr != 0 || p_info.is_null() {
        println!("[*] Azure AD join information not available (not AAD-joined)");
        return Ok(());
    }

    let join_type = unsafe { (*p_info).join_type };
    let join_str = match join_type {
        0 => "Unknown",
        1 => "AAD Joined (Device)",
        2 => "Workplace Joined",
        _ => "Other",
    };

    println!("Join Type    : {} ({})", join_str, join_type);

    let tenant_id = unsafe { (*p_info).p_tenant_id };
    if !tenant_id.is_null() {
        let t = wide_to_str(tenant_id, 128);
        println!("Tenant ID    : {}", t);
    }

    let device_id = unsafe { (*p_info).p_device_id };
    if !device_id.is_null() {
        let d = wide_to_str(device_id, 128);
        println!("Device ID    : {}", d);
    }

    let domain = unsafe { (*p_info).p_id_idp_domain };
    if !domain.is_null() {
        let dom = wide_to_str(domain, 128);
        println!("IdP Domain   : {}", dom);
    }

    unsafe { let _ = net_free_aad_join_information(p_info); };
    Ok(())
}

fn wide_to_str(ptr: *const u16, max: usize) -> WStr {
    let mut s = WStr::new();
    if ptr.is_null() { return s; }
    for i in 0..max {
        let wc = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if wc == 0 { break; }
        s.push(if wc < 128 { wc as u8 } else { b'?' });
    }
    s
}

struct WStr { buf: [u8; 128], len: usize }
impl WStr {
    fn new() -> Self { Self { buf: [0u8; 128], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for WStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
