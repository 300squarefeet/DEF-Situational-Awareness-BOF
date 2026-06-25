#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1562.001", name: "Impair Defenses: Disable or Modify Tools", tactic: "Defense Evasion" },
];

const HKEY_LOCAL_MACHINE: usize = 0x80000002;
const KEY_READ: u32 = 0x20019;
const ERROR_SUCCESS: u32 = 0;
const ERROR_NO_MORE_ITEMS: u32 = 259;

dfr_fn!(reg_open_key_ex_a(hkey: usize, subkey: *const i8, options: u32, sam: u32, result: *mut usize) -> u32, module = "advapi32.dll", api = "RegOpenKeyExA");
dfr_fn!(reg_enum_value_a(hkey: usize, index: u32, name: *mut i8, name_len: *mut u32, reserved: *mut u32, reg_type: *mut u32, data: *mut u8, data_len: *mut u32) -> u32, module = "advapi32.dll", api = "RegEnumValueA");
dfr_fn!(reg_close_key(hkey: usize) -> u32, module = "advapi32.dll", api = "RegCloseKey");

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn state_str(v: u32) -> &'static str {
    match v {
        0 => "Disabled",
        1 => "Block",
        2 => "Audit",
        6 => "Warn",
        _ => "Unknown",
    }
}

fn dump_asr_key(path: *const i8, label: &str) {
    let mut hkey: usize = 0;
    let rc = unsafe { reg_open_key_ex_a(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &mut hkey) };
    let rc = match rc { Ok(v) => v, Err(_) => return };
    if rc != ERROR_SUCCESS { return; }

    println!("\n[*] {}", label);
    println!("{:<40} {}", "GUID", "State");
    println!("{}", "------------------------------------------------");

    for idx in 0..256u32 {
        let mut name = [0i8; 80];
        let mut name_len: u32 = 79;
        let mut data = [0u8; 8];
        let mut data_len: u32 = 8;
        let mut reg_type: u32 = 0;

        let r = unsafe { reg_enum_value_a(hkey, idx, name.as_mut_ptr(), &mut name_len, core::ptr::null_mut(), &mut reg_type, data.as_mut_ptr(), &mut data_len) };
        let r = match r { Ok(v) => v, Err(_) => break };
        if r == ERROR_NO_MORE_ITEMS { break; }
        if r != ERROR_SUCCESS { continue; }

        let guid = cstr_to_str(&name);
        let val = if data_len >= 4 { u32::from_le_bytes([data[0], data[1], data[2], data[3]]) } else if data_len > 0 { data[0] as u32 } else { 0 };
        println!("{:<40} {} ({})", guid, val, state_str(val));
    }

    unsafe { let _ = reg_close_key(hkey); }
}

fn run() -> Result<(), &'static str> {
    obf_cstr! { let path1 = c"SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules"; }
    obf_cstr! { let path2 = c"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules"; }

    dump_asr_key(path1.as_ptr() as *const i8, "Defender ASR Rules");
    dump_asr_key(path2.as_ptr() as *const i8, "Policy ASR Rules");
    Ok(())
}

fn cstr_to_str(buf: &[i8]) -> &str {
    let bytes = unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len()) };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).unwrap_or("?")
}
