#![no_std]
#![cfg_attr(not(test), no_main)]
use common::{dfr_fn, mitre::Technique};
use rustbof::{print, println};
const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1016",
    name: "System Network Configuration Discovery",
    tactic: "Discovery",
}];
const SPI_GETDESKWALLPAPER: u32 = 0x73;
dfr_fn!(system_parameters_info_w(a:u32,p:u32,v:*mut u16,w:u32)->i32,module="user32.dll",api="SystemParametersInfoW");
#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut b = [0u16; 520];
    if unsafe { system_parameters_info_w(SPI_GETDESKWALLPAPER, 520, b.as_mut_ptr(), 0) }
        .unwrap_or(0)
        == 0
    {
        println!("[!] Wallpaper query failed");
        return;
    }
    print!("Wallpaper: ");
    for &c in b.iter().take_while(|&&c| c != 0) {
        if c < 128 {
            print!("{}", c as u8 as char)
        } else {
            print!("?")
        }
    }
    println!("");
}
