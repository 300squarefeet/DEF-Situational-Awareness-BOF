#![no_std]
#![cfg_attr(not(test), no_main)]
use alloc::string::String;
use common::{dfr_fn, mitre::Technique};
use rustbof::{eprintln, println};
const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1218",
    name: "System Binary Proxy Execution",
    tactic: "Defense Evasion",
}];
#[repr(C)]
struct Guid {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}
dfr_fn!(co_initialize_ex(p:*mut core::ffi::c_void,c:u32)->i32,module="ole32.dll",api="CoInitializeEx");
dfr_fn!(co_uninitialize()->(),module="ole32.dll",api="CoUninitialize");
dfr_fn!(clsid_from_string(s:*const u16,g:*mut Guid)->i32,module="ole32.dll",api="CLSIDFromString");
dfr_fn!(co_create_instance(c:*const Guid,o:*mut core::ffi::c_void,ctx:u32,i:*const Guid,p:*mut *mut core::ffi::c_void)->i32,module="ole32.dll",api="CoCreateInstance");
const IID_IUNKNOWN: Guid = Guid {
    d1: 0,
    d2: 0,
    d3: 0,
    d4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46],
};
#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut p = rustbof::data::DataParser::new(args, len);
    let s = String::from(p.get_str());
    if s.is_empty() {
        eprintln!("[!] usage: com-probe <CLSID>");
        return;
    }
    let mut w = [0u16; 64];
    for (i, b) in s.bytes().take(63).enumerate() {
        w[i] = b as u16;
    }
    let mut g = Guid {
        d1: 0,
        d2: 0,
        d3: 0,
        d4: [0; 8],
    };
    if unsafe { clsid_from_string(w.as_ptr(), &mut g) }.unwrap_or(-1) < 0 {
        eprintln!("[!] Invalid CLSID");
        return;
    }
    let hr = unsafe { co_initialize_ex(core::ptr::null_mut(), 0) }.unwrap_or(-1);
    let mut obj = core::ptr::null_mut();
    let cr =
        unsafe { co_create_instance(&g, core::ptr::null_mut(), 1 | 4, &IID_IUNKNOWN, &mut obj) }
            .unwrap_or(-1);
    if cr >= 0 && !obj.is_null() {
        println!(
            "[+] COM class instantiated successfully (HRESULT=0x{:08X})",
            cr as u32
        );
        unsafe {
            let vt = *(obj as *mut *mut usize);
            let release: extern "system" fn(*mut core::ffi::c_void) -> u32 =
                core::mem::transmute(*vt.add(2));
            release(obj);
        }
    } else {
        println!("[-] COM activation failed (HRESULT=0x{:08X})", cr as u32);
    }
    if hr >= 0 {
        unsafe {
            let _ = co_uninitialize();
        }
    }
}
