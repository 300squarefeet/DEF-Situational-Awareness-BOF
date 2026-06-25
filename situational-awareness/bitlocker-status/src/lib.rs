#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::println;
use common::{mitre::Technique, dfr_fn, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
    Technique { id: "T1005", name: "Data from Local System", tactic: "Collection" },
];

const HKEY_LOCAL_MACHINE: usize = 0x80000002;
const KEY_READ: u32 = 0x20019;
const ERROR_SUCCESS: u32 = 0;

dfr_fn!(reg_open_key_ex_a(hkey: usize, subkey: *const i8, options: u32, sam: u32, result: *mut usize) -> u32, module = "advapi32.dll", api = "RegOpenKeyExA");
dfr_fn!(reg_query_value_ex_a(hkey: usize, name: *const i8, reserved: *mut u32, reg_type: *mut u32, data: *mut u8, data_len: *mut u32) -> u32, module = "advapi32.dll", api = "RegQueryValueExA");
dfr_fn!(reg_close_key(hkey: usize) -> u32, module = "advapi32.dll", api = "RegCloseKey");

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);

    obf_cstr! { let fve_path = c"SOFTWARE\\Policies\\Microsoft\\FVE"; }
    obf_cstr! { let status_path = c"SYSTEM\\CurrentControlSet\\Control\\BitLockerStatus"; }

    println!("[*] BitLocker Policy (FVE):");
    dump_fve(fve_path.as_ptr() as *const i8);

    println!("\n[*] BitLocker Boot Status:");
    dump_boot_status(status_path.as_ptr() as *const i8);
}

fn dump_fve(path: *const i8) {
    let mut hkey: usize = 0;
    let rc = unsafe { reg_open_key_ex_a(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &mut hkey) };
    let rc = match rc { Ok(v) => v, Err(_) => { println!("    (unavailable)"); return; } };
    if rc != ERROR_SUCCESS { println!("    (not configured)"); return; }

    obf_cstr! { let v1 = c"RequireActiveDirectoryBackup"; }
    obf_cstr! { let v2 = c"ActiveDirectoryBackup"; }
    obf_cstr! { let v3 = c"EncryptionMethod"; }

    print_dword(hkey, v1.as_ptr() as *const i8, "RequireADBackup");
    print_dword(hkey, v2.as_ptr() as *const i8, "ADBackup");
    print_dword(hkey, v3.as_ptr() as *const i8, "EncryptionMethod");

    unsafe { let _ = reg_close_key(hkey); }
}

fn dump_boot_status(path: *const i8) {
    let mut hkey: usize = 0;
    let rc = unsafe { reg_open_key_ex_a(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &mut hkey) };
    let rc = match rc { Ok(v) => v, Err(_) => { println!("    (unavailable)"); return; } };
    if rc != ERROR_SUCCESS { println!("    (not present)"); return; }

    obf_cstr! { let bs = c"BootStatus"; }
    print_dword(hkey, bs.as_ptr() as *const i8, "BootStatus");

    unsafe { let _ = reg_close_key(hkey); }
}

fn print_dword(hkey: usize, name: *const i8, label: &str) {
    let mut data = [0u8; 4];
    let mut data_len: u32 = 4;
    let mut reg_type: u32 = 0;
    let rc = unsafe { reg_query_value_ex_a(hkey, name, core::ptr::null_mut(), &mut reg_type, data.as_mut_ptr(), &mut data_len) };
    match rc {
        Ok(v) if v == ERROR_SUCCESS => {
            let val = u32::from_le_bytes(data);
            println!("    {}: {}", label, val);
        }
        _ => println!("    {}: (not set)", label),
    }
}
