#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::vec::Vec;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1134.001", name: "Access Token Manipulation: Token Impersonation/Theft", tactic: "Privilege Escalation" },
];

const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_USER_INFO: u32 = 1;
const SYSTEM_PROCESS_INFORMATION: u32 = 5;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;

dfr_fn!(nt_query_system_information(class: u32, buf: *mut u8, len: u32, ret_len: *mut u32) -> i32, module = "ntdll.dll", api = "NtQuerySystemInformation");
dfr_fn!(open_process(access: u32, inherit: i32, pid: u32) -> usize, module = "kernel32.dll", api = "OpenProcess");
dfr_fn!(open_process_token(process: usize, access: u32, token: *mut usize) -> i32, module = "advapi32.dll", api = "OpenProcessToken");
dfr_fn!(get_token_information(token: usize, class: u32, info: *mut u8, len: u32, ret_len: *mut u32) -> i32, module = "advapi32.dll", api = "GetTokenInformation");
dfr_fn!(lookup_account_sid_a(system: *const i8, sid: *const u8, name: *mut i8, name_len: *mut u32, domain: *mut i8, domain_len: *mut u32, use_type: *mut u32) -> i32, module = "advapi32.dll", api = "LookupAccountSidA");
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
    let buf = query_system_processes()?;

    println!("{:<8} {:<30} {}", "PID", "Process", "User");
    println!("{}", "-----------------------------------------------------------");

    let mut offset = 0usize;
    loop {
        if offset + 88 > buf.len() { break; }
        let next = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]) as usize;
        let pid = u32::from_le_bytes([buf[offset+80], buf[offset+81], buf[offset+82], buf[offset+83]]);
        let name_len = u16::from_le_bytes([buf[offset+56], buf[offset+57]]) as usize;
        let name_ptr_val = u64::from_le_bytes([buf[offset+64], buf[offset+65], buf[offset+66], buf[offset+67], buf[offset+68], buf[offset+69], buf[offset+70], buf[offset+71]]);

        let proc_name = if name_ptr_val != 0 && name_len > 0 {
            let wstr = unsafe { core::slice::from_raw_parts(name_ptr_val as *const u16, name_len / 2) };
            wide_to_str(wstr)
        } else {
            [b'S', b'y', b's', b't', b'e', b'm', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        };

        let user = resolve_token_user(pid);
        let pname = core::str::from_utf8(&proc_name).unwrap_or("?").trim_end_matches('\0');
        let uname = core::str::from_utf8(&user).unwrap_or("?").trim_end_matches('\0');
        if pid != 0 { println!("{:<8} {:<30} {}", pid, pname, uname); }

        if next == 0 { break; }
        offset += next;
    }
    Ok(())
}

fn query_system_processes() -> Result<Vec<u8>, &'static str> {
    let mut size: u32 = 131072;
    loop {
        let mut v: Vec<u8> = alloc::vec![0u8; size as usize];
        let mut ret_len: u32 = 0;
        let status = unsafe { nt_query_system_information(SYSTEM_PROCESS_INFORMATION, v.as_mut_ptr(), size, &mut ret_len) }.map_err(|_| "resolve failed")?;
        if status == 0 { return Ok(v); }
        if status == STATUS_INFO_LENGTH_MISMATCH {
            if size >= 64 * 1024 * 1024 { return Err("buf too large"); }
            size = size.saturating_mul(2);
        } else { return Err("query failed"); }
    }
}

fn resolve_token_user(pid: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    let hproc = match unsafe { open_process(PROCESS_QUERY_INFORMATION, 0, pid) } { Ok(h) if h != 0 => h, _ => return out };
    let mut htoken: usize = 0;
    let ok = match unsafe { open_process_token(hproc, TOKEN_QUERY, &mut htoken) } { Ok(v) => v, _ => { unsafe { let _ = close_handle(hproc); } return out; } };
    if ok == 0 { unsafe { let _ = close_handle(hproc); } return out; }

    let mut info = [0u8; 128];
    let mut ret_len: u32 = 0;
    let ok2 = match unsafe { get_token_information(htoken, TOKEN_USER_INFO, info.as_mut_ptr(), 128, &mut ret_len) } { Ok(v) => v, _ => 0 };
    if ok2 != 0 {
        let sid_ptr = u64::from_le_bytes([info[0], info[1], info[2], info[3], info[4], info[5], info[6], info[7]]) as *const u8;
        let mut name_buf = [0i8; 64];
        let mut domain_buf = [0i8; 64];
        let mut name_len: u32 = 63;
        let mut domain_len: u32 = 63;
        let mut use_type: u32 = 0;
        if let Ok(r) = unsafe { lookup_account_sid_a(core::ptr::null(), sid_ptr, name_buf.as_mut_ptr(), &mut name_len, domain_buf.as_mut_ptr(), &mut domain_len, &mut use_type) } {
            if r != 0 {
                let mut pos = 0usize;
                for i in 0..domain_len as usize { if pos < 31 { out[pos] = domain_buf[i] as u8; pos += 1; } }
                if pos < 31 { out[pos] = b'\\'; pos += 1; }
                for i in 0..name_len as usize { if pos < 31 { out[pos] = name_buf[i] as u8; pos += 1; } }
            }
        }
    }

    unsafe { let _ = close_handle(htoken); let _ = close_handle(hproc); }
    out
}

fn wide_to_str(w: &[u16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, &c) in w.iter().enumerate() {
        if i >= 31 { break; }
        out[i] = if c < 128 { c as u8 } else { b'?' };
    }
    out
}
