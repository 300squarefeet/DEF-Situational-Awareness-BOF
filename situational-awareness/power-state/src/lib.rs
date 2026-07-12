#![no_std]
#![cfg_attr(not(test), no_main)]
use common::{dfr_fn, mitre::Technique};
use rustbof::{eprintln, println};
const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1082",
    name: "System Information Discovery",
    tactic: "Discovery",
}];
#[repr(C)]
struct Power {
    ac: u8,
    flag: u8,
    percent: u8,
    reserved: u8,
    lifetime: u32,
    full: u32,
}
dfr_fn!(get_system_power_status(p:*mut Power)->i32,module="kernel32.dll",api="GetSystemPowerStatus");
#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut p = Power {
        ac: 255,
        flag: 0,
        percent: 255,
        reserved: 0,
        lifetime: u32::MAX,
        full: u32::MAX,
    };
    match unsafe { get_system_power_status(&mut p) } {
        Ok(v) if v != 0 => {
            println!(
                "Power source : {}",
                match p.ac {
                    0 => "Battery",
                    1 => "AC",
                    _ => "Unknown",
                }
            );
            if p.percent <= 100 {
                println!("Battery     : {}%", p.percent);
            }
            println!(
                "Form factor : {}",
                if p.flag & 128 != 0 {
                    "Desktop/server (no battery)"
                } else {
                    "Portable/battery-equipped"
                }
            );
        }
        _ => eprintln!("[!] power status unavailable"),
    }
}
