#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::println;
use common::{mitre::Technique, dfr_fn, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1518", name: "Software Discovery", tactic: "Discovery" },
];

const INVALID_HANDLE: usize = usize::MAX;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

dfr_fn!(get_env_var(name: *const i8, buf: *mut i8, size: u32) -> u32, module = "kernel32.dll", api = "GetEnvironmentVariableA");
dfr_fn!(find_first_file(name: *const i8, data: *mut u8) -> usize, module = "kernel32.dll", api = "FindFirstFileA");
dfr_fn!(find_next_file(handle: usize, data: *mut u8) -> i32, module = "kernel32.dll", api = "FindNextFileA");
dfr_fn!(find_close(handle: usize) -> i32, module = "kernel32.dll", api = "FindClose");

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);

    let mut profile = [0i8; 260];
    obf_cstr! { let v_profile = c"USERPROFILE"; }
    let plen = unsafe { get_env_var(v_profile.as_ptr() as *const i8, profile.as_mut_ptr(), 260) }.unwrap_or(0) as usize;
    if plen == 0 { return; }

    list_extensions(&profile, plen, b"\\.vscode\\extensions\\*\0", "VS Code");
    list_extensions(&profile, plen, b"\\.cursor\\extensions\\*\0", "Cursor");
    list_extensions(&profile, plen, b"\\.windsurf\\extensions\\*\0", "Windsurf");
}

fn list_extensions(base: &[i8; 260], base_len: usize, suffix: &[u8], ide: &str) {
    let mut path = [0i8; 512];
    if base_len + suffix.len() >= 512 { return; }
    for i in 0..base_len { path[i] = base[i]; }
    for (i, &b) in suffix.iter().enumerate() { path[base_len + i] = b as i8; }

    let mut fd = [0u8; 592];
    let h = unsafe { find_first_file(path.as_ptr(), fd.as_mut_ptr()) }.unwrap_or(INVALID_HANDLE);
    if h == INVALID_HANDLE { return; }

    println!("[*] {} extensions:", ide);
    loop {
        let attrs = u32::from_le_bytes([fd[0], fd[1], fd[2], fd[3]]);
        if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
            let name = &fd[44..]; // cFileName offset in WIN32_FIND_DATAA
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            let s = core::str::from_utf8(&name[..end]).unwrap_or("?");
            if s != "." && s != ".." { println!("    {}", s); }
        }
        if unsafe { find_next_file(h, fd.as_mut_ptr()) }.unwrap_or(0) == 0 { break; }
    }
    unsafe { let _ = find_close(h); }
}
