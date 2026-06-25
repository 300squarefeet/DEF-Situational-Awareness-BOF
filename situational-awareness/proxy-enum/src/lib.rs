#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1016", name: "System Network Configuration Discovery", tactic: "Discovery" },
];

const HKEY_CURRENT_USER: usize = 0x80000001;
const KEY_READ: u32 = 0x20019;
const ERROR_SUCCESS: u32 = 0;

dfr_fn!(reg_open_key_ex_a(hkey: usize, sub: *const i8, opts: u32, sam: u32, out: *mut usize) -> u32, module = "advapi32.dll", api = "RegOpenKeyExA");
dfr_fn!(reg_query_value_ex_a(hkey: usize, name: *const i8, reserved: *mut u32, reg_type: *mut u32, data: *mut u8, data_len: *mut u32) -> u32, module = "advapi32.dll", api = "RegQueryValueExA");
dfr_fn!(reg_close_key(hkey: usize) -> u32, module = "advapi32.dll", api = "RegCloseKey");
dfr_fn!(get_environment_variable_a(name: *const i8, buf: *mut u8, size: u32) -> u32, module = "kernel32.dll", api = "GetEnvironmentVariableA");

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {}
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn query_reg_str(hkey: usize, name: *const i8, buf: &mut [u8]) -> Option<usize> {
    let mut len = buf.len() as u32;
    let mut rtype: u32 = 0;
    let rc = unsafe { reg_query_value_ex_a(hkey, name, core::ptr::null_mut(), &mut rtype, buf.as_mut_ptr(), &mut len) }.ok()?;
    if rc == ERROR_SUCCESS && len > 0 { Some((len - 1) as usize) } else { None }
}

fn query_env(name: *const i8, buf: &mut [u8]) -> Option<usize> {
    let n = unsafe { get_environment_variable_a(name, buf.as_mut_ptr(), buf.len() as u32) }.ok()?;
    if n > 0 { Some(n as usize) } else { None }
}

fn run() -> Result<(), &'static str> {
    obf_cstr! { let subkey = c"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"; }
    let mut hkey: usize = 0;
    let rc = unsafe { reg_open_key_ex_a(HKEY_CURRENT_USER, subkey.as_ptr() as *const i8, 0, KEY_READ, &mut hkey) }.map_err(|_| "resolve failed")?;
    if rc == ERROR_SUCCESS {
        let mut buf = [0u8; 512];
        obf_cstr! { let pe = c"ProxyEnable"; }
        if let Some(_) = query_reg_str(hkey, pe.as_ptr() as *const i8, &mut buf) {
            let v = if buf[0] == 1 { "Enabled" } else { "Disabled" };
            println!("[+] ProxyEnable: {}", v);
        }
        obf_cstr! { let ps = c"ProxyServer"; }
        buf.iter_mut().for_each(|b| *b = 0);
        if let Some(n) = query_reg_str(hkey, ps.as_ptr() as *const i8, &mut buf) {
            println!("[+] ProxyServer: {}", core::str::from_utf8(&buf[..n]).unwrap_or("?"));
        }
        obf_cstr! { let ac = c"AutoConfigURL"; }
        buf.iter_mut().for_each(|b| *b = 0);
        if let Some(n) = query_reg_str(hkey, ac.as_ptr() as *const i8, &mut buf) {
            println!("[+] AutoConfigURL: {}", core::str::from_utf8(&buf[..n]).unwrap_or("?"));
        }
        unsafe { let _ = reg_close_key(hkey); }
    } else {
        println!("[-] Registry key not accessible");
    }

    let mut buf = [0u8; 512];
    obf_cstr! { let hp = c"HTTP_PROXY"; }
    if let Some(n) = query_env(hp.as_ptr() as *const i8, &mut buf) {
        println!("[+] HTTP_PROXY: {}", core::str::from_utf8(&buf[..n]).unwrap_or("?"));
    }
    obf_cstr! { let hps = c"HTTPS_PROXY"; }
    buf.iter_mut().for_each(|b| *b = 0);
    if let Some(n) = query_env(hps.as_ptr() as *const i8, &mut buf) {
        println!("[+] HTTPS_PROXY: {}", core::str::from_utf8(&buf[..n]).unwrap_or("?"));
    }
    obf_cstr! { let np = c"NO_PROXY"; }
    buf.iter_mut().for_each(|b| *b = 0);
    if let Some(n) = query_env(np.as_ptr() as *const i8, &mut buf) {
        println!("[+] NO_PROXY: {}", core::str::from_utf8(&buf[..n]).unwrap_or("?"));
    }
    Ok(())
}
