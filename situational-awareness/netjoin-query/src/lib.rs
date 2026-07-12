#![no_std]
#![cfg_attr(not(test), no_main)]
use common::{dfr_fn, mitre::Technique};
use rustbof::{eprintln, print, println};
const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1016",
    name: "System Network Configuration Discovery",
    tactic: "Discovery",
}];
dfr_fn!(net_get_join_information(server: *const u16, name: *mut *mut u16, status: *mut u32) -> u32, module = "netapi32.dll", api = "NetGetJoinInformation");
dfr_fn!(net_api_buffer_free(buf: *mut core::ffi::c_void) -> u32, module = "netapi32.dll", api = "NetApiBufferFree");
#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    if let Err(e) = run() {
        eprintln!("[!] {}", e);
    }
}
fn run() -> Result<(), &'static str> {
    let mut name: *mut u16 = core::ptr::null_mut();
    let mut status = 0u32;
    let rc = unsafe { net_get_join_information(core::ptr::null(), &mut name, &mut status) }
        .map_err(|_| "resolver failed")?;
    if rc != 0 || name.is_null() {
        return Err("join query failed");
    }
    let len = (0..256)
        .position(|i| unsafe { *name.add(i) == 0 })
        .unwrap_or(255);
    println!(
        "Join status: {}",
        match status {
            1 => "Unjoined",
            2 => "Workgroup",
            3 => "Domain",
            _ => "Unknown",
        }
    );
    print!("Join name: ");
    for i in 0..len {
        let c = unsafe { *name.add(i) };
        if c < 128 {
            print!("{}", c as u8 as char);
        } else {
            print!("?");
        }
    }
    println!("");
    unsafe {
        let _ = net_api_buffer_free(name as *mut _);
    }
    Ok(())
}
