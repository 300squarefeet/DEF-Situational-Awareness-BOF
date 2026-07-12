#![no_std]
#![cfg_attr(not(test), no_main)]

use common::{dfr_fn, mitre::Technique, obf_cstr};
use rustbof::{eprintln, println};

const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1518",
    name: "Software Discovery",
    tactic: "Discovery",
}];
const HKLM: usize = 0x8000_0002;
const KEY_READ: u32 = 0x0002_0019;
const KEY_WOW64_64KEY: u32 = 0x0100;
const KEY_WOW64_32KEY: u32 = 0x0200;
const ERROR_SUCCESS: u32 = 0;
const ERROR_NO_MORE_ITEMS: u32 = 259;

dfr_fn!(reg_open_key_ex_a(h: usize, sub: *const i8, opt: u32, sam: u32, out: *mut usize) -> u32, module = "advapi32.dll", api = "RegOpenKeyExA");
dfr_fn!(reg_enum_key_ex_a(h: usize, index: u32, name: *mut u8, len: *mut u32, reserved: *mut u32, class: *mut u8, class_len: *mut u32, time: *mut u8) -> u32, module = "advapi32.dll", api = "RegEnumKeyExA");
dfr_fn!(reg_close_key(h: usize) -> u32, module = "advapi32.dll", api = "RegCloseKey");

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(n) => println!("[+] Installed application entries: {}", n),
        Err(e) => eprintln!("[!] {}", e),
    }
}

fn run() -> Result<u32, &'static str> {
    obf_cstr! { let path = c"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"; }
    let mut total = 0;
    for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        let mut key = 0usize;
        let rc = unsafe { reg_open_key_ex_a(HKLM, path.as_ptr(), 0, KEY_READ | view, &mut key) }
            .map_err(|_| "registry resolver failed")?;
        if rc != ERROR_SUCCESS {
            continue;
        }
        let mut index = 0u32;
        loop {
            let mut name = [0u8; 256];
            let mut len = 255u32;
            let rc = unsafe {
                reg_enum_key_ex_a(
                    key,
                    index,
                    name.as_mut_ptr(),
                    &mut len,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            }
            .unwrap_or(u32::MAX);
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc == ERROR_SUCCESS {
                total += 1;
            }
            index += 1;
            if index > 8192 {
                break;
            }
        }
        unsafe {
            let _ = reg_close_key(key);
        }
    }
    Ok(total)
}
