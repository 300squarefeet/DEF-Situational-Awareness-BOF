#![no_std]
#![cfg_attr(not(test), no_main)]
use common::{dfr_fn, mitre::Technique, obf_cstr};
use rustbof::println;
const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1069.001",
    name: "Permission Groups Discovery: Local Groups",
    tactic: "Discovery",
}];
const HKLM: usize = 0x80000002;
const KEY_READ: u32 = 0x20019;
dfr_fn!(reg_open_key_ex_a(h:usize,s:*const i8,o:u32,a:u32,out:*mut usize)->u32,module="advapi32.dll",api="RegOpenKeyExA");
dfr_fn!(reg_query_value_ex_a(h:usize,n:*const i8,r:*mut u32,t:*mut u32,d:*mut u8,l:*mut u32)->u32,module="advapi32.dll",api="RegQueryValueExA");
dfr_fn!(reg_close_key(h:usize)->u32,module="advapi32.dll",api="RegCloseKey");
#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    obf_cstr! {let base=c"SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2";}
    let mut root = 0usize;
    if unsafe { reg_open_key_ex_a(HKLM, base.as_ptr(), 0, KEY_READ, &mut root) }.unwrap_or(1) != 0 {
        println!("[-] No AppLocker policy configured");
        return;
    }
    for (label, name) in [
        ("Executable", c"Exe"),
        ("MSI", c"Msi"),
        ("Script", c"Script"),
        ("DLL", c"Dll"),
        ("Packaged app", c"Appx"),
    ] {
        let mut key = 0usize;
        if unsafe { reg_open_key_ex_a(root, name.as_ptr(), 0, KEY_READ, &mut key) }.unwrap_or(1)
            == 0
        {
            let mut v = [0u8; 4];
            let mut l = 4;
            let mut t = 0;
            obf_cstr! {let en=c"EnforcementMode";}
            let rc = unsafe {
                reg_query_value_ex_a(
                    key,
                    en.as_ptr(),
                    core::ptr::null_mut(),
                    &mut t,
                    v.as_mut_ptr(),
                    &mut l,
                )
            }
            .unwrap_or(1);
            let mode = if rc == 0 {
                match u32::from_le_bytes(v) {
                    1 => "Enforced",
                    2 => "Audit only",
                    _ => "Not configured",
                }
            } else {
                "Configured"
            };
            println!("{:<14}: {}", label, mode);
            unsafe {
                let _ = reg_close_key(key);
            }
        }
    }
    unsafe {
        let _ = reg_close_key(root);
    }
}
