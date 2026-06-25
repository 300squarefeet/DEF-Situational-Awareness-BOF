#![no_std]
#![cfg_attr(not(test), no_main)]

use core::ffi::c_void;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1087.001", name: "Local Account Discovery", tactic: "Discovery" },
];

const EVT_QUERY_CHANNEL_PATH: u32 = 0x1;
const EVT_QUERY_REVERSE_DIRECTION: u32 = 0x200;
const EVT_RENDER_EVENT_XML: u32 = 1;

dfr_fn!(load_library_a(name: *const i8) -> *mut c_void, module = "kernel32.dll", api = "LoadLibraryA");
dfr_fn!(evt_query(session: *mut c_void, path: *const u16, query: *const u16, flags: u32) -> *mut c_void, module = "wevtapi.dll", api = "EvtQuery");
dfr_fn!(evt_next(result_set: *mut c_void, count: u32, events: *mut *mut c_void, timeout: u32, flags: u32, returned: *mut u32) -> i32, module = "wevtapi.dll", api = "EvtNext");
dfr_fn!(evt_render(context: *mut c_void, fragment: *mut c_void, flags: u32, buf_size: u32, buf: *mut u8, used: *mut u32, prop_count: *mut u32) -> i32, module = "wevtapi.dll", api = "EvtRender");
dfr_fn!(evt_close(handle: *mut c_void) -> i32, module = "wevtapi.dll", api = "EvtClose");

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {}
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn to_wide(s: &[u8], buf: &mut [u16]) -> usize {
    let n = s.len().min(buf.len() - 1);
    for i in 0..n { buf[i] = s[i] as u16; }
    buf[n] = 0;
    n
}

fn extract_username(xml: &[u16], used: usize) -> Option<&[u16]> {
    // Search for "TargetUserName'>" pattern in wide chars
    let tag: &[u8] = b"TargetUserName'>";
    let needle: &[u8] = b"TargetUserName";
    let len = used / 2;
    let slice = unsafe { core::slice::from_raw_parts(xml.as_ptr(), len) };
    // find TargetUserName followed by >
    let nlen = needle.len();
    let mut i = 0;
    while i + nlen + 2 < len {
        let mut matched = true;
        for j in 0..nlen {
            if slice[i + j] != needle[j] as u16 { matched = false; break; }
        }
        if matched {
            // skip to next '>'
            let mut k = i + nlen;
            while k < len && slice[k] != b'>' as u16 { k += 1; }
            k += 1; // past '>'
            let start = k;
            while k < len && slice[k] != b'<' as u16 { k += 1; }
            if k > start { return Some(&slice[start..k]); }
        }
        i += 1;
    }
    None
}

fn run() -> Result<(), &'static str> {
    // Load wevtapi.dll
    obf_cstr! { let dll = c"wevtapi.dll"; }
    unsafe { load_library_a(dll.as_ptr() as *const i8) }.map_err(|_| "resolve failed")?;

    let mut channel = [0u16; 16];
    to_wide(b"Security", &mut channel);
    let mut query_str = [0u16; 80];
    to_wide(b"*[System[(EventID=4624)]]", &mut query_str);

    let flags = EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION;
    let hquery = unsafe { evt_query(core::ptr::null_mut(), channel.as_ptr(), query_str.as_ptr(), flags) }.map_err(|_| "resolve failed")?;
    if hquery.is_null() { return Err("query failed"); }

    println!("[+] Recent logon events (EventID 4624):");
    println!("{:<4} {}", "#", "TargetUserName");
    println!("{}", "----------------------------------------");

    let mut printed = 0u32;
    let mut events: [*mut c_void; 1] = [core::ptr::null_mut()];

    while printed < 10 {
        let mut returned: u32 = 0;
        let ok = unsafe { evt_next(hquery, 1, events.as_mut_ptr(), 1000, 0, &mut returned) }.map_err(|_| "resolve failed")?;
        if ok == 0 || returned == 0 { break; }

        let mut buf = [0u8; 4096];
        let mut used: u32 = 0;
        let mut prop_count: u32 = 0;
        let rendered = unsafe { evt_render(core::ptr::null_mut(), events[0], EVT_RENDER_EVENT_XML, buf.len() as u32, buf.as_mut_ptr(), &mut used, &mut prop_count) }.map_err(|_| "resolve failed")?;

        if rendered != 0 && used > 0 {
            let xml = unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u16, used as usize / 2) };
            if let Some(name) = extract_username(xml, used as usize) {
                let mut narrow = [0u8; 64];
                let n = name.len().min(63);
                for i in 0..n { narrow[i] = name[i] as u8; }
                let s = core::str::from_utf8(&narrow[..n]).unwrap_or("?");
                printed += 1;
                println!("{:<4} {}", printed, s);
            }
        }
        unsafe { let _ = evt_close(events[0]); }
    }

    unsafe { let _ = evt_close(hquery); }
    Ok(())
}
