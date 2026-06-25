#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::println;
use common::{mitre::Technique, dfr_fn, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1518.001", name: "Security Software Discovery", tactic: "Discovery" },
];

dfr_fn!(get_module_handle(name: *const i8) -> usize, module = "kernel32.dll", api = "GetModuleHandleA");
dfr_fn!(get_proc_address(module: usize, name: *const i8) -> usize, module = "kernel32.dll", api = "GetProcAddress");

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);

    obf_cstr! { let amsi = c"amsi.dll"; }
    obf_cstr! { let ntdll = c"ntdll.dll"; }
    obf_cstr! { let etw_fn = c"EtwEventWrite"; }

    let amsi_h = unsafe { get_module_handle(amsi.as_ptr() as *const i8) }.unwrap_or(0);
    println!("[+] amsi.dll: {}", if amsi_h != 0 { "loaded" } else { "not loaded" });

    let ntdll_h = unsafe { get_module_handle(ntdll.as_ptr() as *const i8) }.unwrap_or(0);
    if ntdll_h != 0 {
        let etw = unsafe { get_proc_address(ntdll_h, etw_fn.as_ptr() as *const i8) }.unwrap_or(0);
        println!("[+] ETW (EtwEventWrite): {}", if etw != 0 { "present" } else { "absent" });
    } else {
        println!("[+] ETW (EtwEventWrite): absent (ntdll not found)");
    }
}
