#![no_std]
#![cfg_attr(not(test), no_main)]
use common::{dfr_fn, mitre::Technique};
use rustbof::println;
const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1082",
    name: "System Information Discovery",
    tactic: "Discovery",
}];
const HKLM: usize = 0x80000002;
const KEY_READ: u32 = 0x20019;
dfr_fn!(reg_open_key_ex_a(h:usize,s:*const i8,o:u32,a:u32,out:*mut usize)->u32,module="advapi32.dll",api="RegOpenKeyExA");
dfr_fn!(reg_close_key(h:usize)->u32,module="advapi32.dll",api="RegCloseKey");
fn exists(p: &[u8]) -> bool {
    let mut h = 0usize;
    let ok = unsafe { reg_open_key_ex_a(HKLM, p.as_ptr() as *const i8, 0, KEY_READ, &mut h) }
        .unwrap_or(1)
        == 0;
    if ok {
        unsafe {
            let _ = reg_close_key(h);
        }
    }
    ok
}
#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let checks: [(&str, &[u8]); 3] = [
        ("Enrollment records", b"SOFTWARE\\Microsoft\\Enrollments\0"),
        (
            "Provisioning accounts",
            b"SOFTWARE\\Microsoft\\Provisioning\\OMADM\\Accounts\0",
        ),
        (
            "PolicyManager",
            b"SOFTWARE\\Microsoft\\PolicyManager\\current\\device\0",
        ),
    ];
    let mut score = 0;
    for (n, p) in checks {
        let yes = exists(p);
        if yes {
            score += 1;
        }
        println!("{:<24}: {}", n, if yes { "present" } else { "absent" });
    }
    println!(
        "MDM posture score: {}/3 ({})",
        score,
        if score >= 2 {
            "likely managed"
        } else if score == 1 {
            "possible/stale enrollment"
        } else {
            "not detected"
        }
    );
}
