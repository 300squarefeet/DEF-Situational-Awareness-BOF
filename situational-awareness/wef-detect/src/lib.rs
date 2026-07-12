#![no_std]
#![cfg_attr(not(test), no_main)]
use common::{dfr_fn, mitre::Technique, obf_cstr};
use rustbof::println;
const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1518.001",
    name: "Security Software Discovery",
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
    obf_cstr! {let key=c"SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding\\SubscriptionManager";}
    let mut h = 0usize;
    if unsafe { reg_open_key_ex_a(HKLM, key.as_ptr(), 0, KEY_READ, &mut h) }.unwrap_or(1) == 0 {
        println!("[+] WEF SubscriptionManager policy is configured");
        for i in 1..=16 {
            let mut n = [0i8; 4];
            n[0] = (b'0' + (i / 10) as u8) as i8;
            n[1] = (b'0' + (i % 10) as u8) as i8;
            if i < 10 {
                n[0] = n[1];
                n[1] = 0;
            }
            let mut d = [0u8; 512];
            let mut l = 511;
            let mut t = 0;
            if unsafe {
                reg_query_value_ex_a(
                    h,
                    n.as_ptr(),
                    core::ptr::null_mut(),
                    &mut t,
                    d.as_mut_ptr(),
                    &mut l,
                )
            }
            .unwrap_or(1)
                == 0
            {
                let end = d.iter().position(|&b| b == 0).unwrap_or(l as usize);
                println!(
                    "  {}",
                    core::str::from_utf8(&d[..end]).unwrap_or("<non-UTF8>")
                );
            }
        }
        unsafe {
            let _ = reg_close_key(h);
        }
    } else {
        println!("[-] No WEF SubscriptionManager policy detected");
    }
}
