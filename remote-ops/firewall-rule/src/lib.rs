#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1562.004", name: "Disable or Modify System Firewall", tactic: "Defense Evasion" },
];

const HKEY_LOCAL_MACHINE: usize = 0x80000002;
const KEY_READ: u32 = 0x20019;
const ERROR_SUCCESS: u32 = 0;
const ERROR_NO_MORE_ITEMS: u32 = 259;

dfr_fn!(reg_open_key_ex_a(hkey: usize, sub: *const i8, opts: u32, sam: u32, out: *mut usize) -> u32, module = "advapi32.dll", api = "RegOpenKeyExA");
dfr_fn!(reg_enum_value_a(hkey: usize, idx: u32, name: *mut i8, name_len: *mut u32, reserved: *mut u32, rtype: *mut u32, data: *mut u8, data_len: *mut u32) -> u32, module = "advapi32.dll", api = "RegEnumValueA");
dfr_fn!(reg_close_key(hkey: usize) -> u32, module = "advapi32.dll", api = "RegCloseKey");

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {}
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn extract_name(data: &[u8], len: usize) -> &str {
    let s = core::str::from_utf8(&data[..len]).unwrap_or("");
    // Firewall rule values are pipe-delimited; first field after version is often the name
    // Format: "v2.XX|Action=...|Name=...|..."
    for part in s.split('|') {
        if part.len() > 5 && part.as_bytes()[..5] == *b"Name=" {
            return &part[5..];
        }
    }
    if s.len() > 60 { &s[..60] } else { s }
}

fn run() -> Result<(), &'static str> {
    obf_cstr! { let subkey = c"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"; }
    let mut hkey: usize = 0;
    let rc = unsafe { reg_open_key_ex_a(HKEY_LOCAL_MACHINE, subkey.as_ptr() as *const i8, 0, KEY_READ, &mut hkey) }.map_err(|_| "resolve failed")?;
    if rc != ERROR_SUCCESS { return Err("key open failed"); }

    println!("[+] Firewall Rules (first 20):");
    println!("{:<4} {}", "#", "Rule Name");
    println!("{}", "----------------------------------------");

    let mut name_buf = [0i8; 256];
    let mut data_buf = [0u8; 2048];
    let mut count = 0u32;

    loop {
        if count >= 20 { break; }
        let mut name_len = 256u32;
        let mut data_len = 2048u32;
        let mut rtype: u32 = 0;
        let rc = unsafe { reg_enum_value_a(hkey, count, name_buf.as_mut_ptr(), &mut name_len, core::ptr::null_mut(), &mut rtype, data_buf.as_mut_ptr(), &mut data_len) }.map_err(|_| "resolve failed")?;
        if rc == ERROR_NO_MORE_ITEMS { break; }
        if rc != ERROR_SUCCESS { count += 1; continue; }
        let rule_name = extract_name(&data_buf, data_len.saturating_sub(1) as usize);
        println!("{:<4} {}", count + 1, rule_name);
        count += 1;
    }

    unsafe { let _ = reg_close_key(hkey); }
    Ok(())
}
