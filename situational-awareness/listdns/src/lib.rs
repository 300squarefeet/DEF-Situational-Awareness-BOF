// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1016", name: "System Network Configuration Discovery", tactic: "Discovery" },
];

const HKLM: isize = 0x80000002u32 as i32 as isize;
const KEY_READ: u32 = 0x20019;
const ERROR_NO_MORE_ITEMS: i32 = 259;

dfr_fn!(
    reg_open_key_ex_a(
        hKey: isize,
        lpSubKey: *const i8,
        ulOptions: u32,
        samDesired: u32,
        phkResult: *mut isize
    ) -> i32,
    module = "advapi32.dll",
    api    = "RegOpenKeyExA"
);

dfr_fn!(
    reg_enum_key_ex_a(
        hKey: isize,
        dwIndex: u32,
        lpName: *mut i8,
        lpcchName: *mut u32,
        lpReserved: *mut u32,
        lpClass: *mut i8,
        lpcchClass: *mut u32,
        lpftLastWriteTime: *mut u8
    ) -> i32,
    module = "advapi32.dll",
    api    = "RegEnumKeyExA"
);

dfr_fn!(
    reg_query_value_ex_a(
        hKey: isize,
        lpValueName: *const i8,
        lpReserved: *mut u32,
        lpType: *mut u32,
        lpData: *mut u8,
        lpcbData: *mut u32
    ) -> i32,
    module = "advapi32.dll",
    api    = "RegQueryValueExA"
);

dfr_fn!(
    reg_close_key(hKey: isize) -> i32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
);

// ---- helpers ---------------------------------------------------------------

struct CStr { buf: [u8; 512], len: usize }
impl CStr {
    fn new() -> Self { Self { buf: [0u8; 512], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for CStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}

fn ptr_to_cstr(p: *const u8, max: usize) -> CStr {
    let mut s = CStr::new();
    if p.is_null() { return s; }
    for i in 0..max {
        let b = unsafe { core::ptr::read_volatile(p.add(i)) };
        if b == 0 { break; }
        s.push(b);
    }
    s
}

fn cstr_from_ibuf(buf: &[i8], len: usize) -> CStr {
    let mut s = CStr::new();
    let count = len.min(buf.len());
    for i in 0..count {
        s.push(buf[i] as u8);
    }
    s
}

// ---- entry -----------------------------------------------------------------

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    let base_path = b"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\0";
    let mut h_root: isize = 0;
    let r = unsafe {
        reg_open_key_ex_a(
            HKLM,
            base_path.as_ptr() as *const i8,
            0,
            KEY_READ,
            &mut h_root,
        )
    }.unwrap_or(-1);
    if r != 0 || h_root == 0 {
        println!("[*] No Tcpip interfaces key found.");
        return Ok(());
    }

    println!("DNS Servers:");
    let mut idx: u32 = 0;
    loop {
        let mut name_buf = [0i8; 256];
        let mut name_len: u32 = 256;
        let er = unsafe {
            reg_enum_key_ex_a(
                h_root,
                idx,
                name_buf.as_mut_ptr(),
                &mut name_len,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        }.unwrap_or(ERROR_NO_MORE_ITEMS);
        if er == ERROR_NO_MORE_ITEMS { break; }
        if er != 0 { idx += 1; continue; }

        let guid = cstr_from_ibuf(&name_buf, name_len as usize);

        let mut h_iface: isize = 0;
        let sr = unsafe {
            reg_open_key_ex_a(
                h_root,
                name_buf.as_ptr(),
                0,
                KEY_READ,
                &mut h_iface,
            )
        }.unwrap_or(-1);
        if sr == 0 && h_iface != 0 {
            // NameServer (static) and DhcpNameServer (DHCP-assigned)
            let val_names: [(&[u8], &str); 2] = [
                (b"NameServer\0", "Static"),
                (b"DhcpNameServer\0", "DHCP"),
            ];
            for (val_name, label) in &val_names {
                let mut vtype: u32 = 0;
                let mut data = [0u8; 512];
                let mut dlen: u32 = 512;
                let qr = unsafe {
                    reg_query_value_ex_a(
                        h_iface,
                        val_name.as_ptr() as *const i8,
                        core::ptr::null_mut(),
                        &mut vtype,
                        data.as_mut_ptr(),
                        &mut dlen,
                    )
                }.unwrap_or(-1);
                if qr == 0 && dlen > 1 {
                    let dns = ptr_to_cstr(data.as_ptr(), dlen as usize);
                    println!("  {} [{}]: {}", guid, label, dns);
                }
            }
            unsafe { let _ = reg_close_key(h_iface); };
        }
        idx += 1;
    }

    unsafe { let _ = reg_close_key(h_root); };
    Ok(())
}
