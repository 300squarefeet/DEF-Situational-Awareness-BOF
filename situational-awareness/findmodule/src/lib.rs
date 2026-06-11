// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1057", name: "Process Discovery", tactic: "Discovery" },
];

const STATUS_SUCCESS: i32 = 0;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_VM_READ: u32 = 0x0010;
// ProcessBasicInformation = 0
const PROCESS_BASIC_INFORMATION: u32 = 0;

dfr_fn!(
    open_process(desired_access: u32, inherit: i32, pid: u32) -> usize,
    module = "kernel32.dll",
    api    = "OpenProcess"
);

dfr_fn!(
    close_handle(handle: usize) -> i32,
    module = "kernel32.dll",
    api    = "CloseHandle"
);

dfr_fn!(
    read_process_memory(
        process: usize,
        base: usize,
        buf: *mut u8,
        size: usize,
        read: *mut usize,
    ) -> i32,
    module = "kernel32.dll",
    api    = "ReadProcessMemory"
);

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    let current_pid = unsafe { get_current_pid() };
    println!("MODULES IN PID {}:", current_pid);
    println!("{}", "--------------------------------------------");
    println!("{:<18} {:<12} {}", "Base", "Size", "Module");

    let hproc = unsafe { open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, current_pid) }
        .map_err(|_| "resolve")?;
    if hproc == 0 { return Err("proc open failed"); }

    // NtQueryInformationProcess(ProcessBasicInformation) — 5 args
    use common::syscalls::{SyscallEntry, resolve, do_syscall5};
    static ENTRY: SyscallEntry = SyscallEntry::new();
    const HASH: u32 = common::hash::djb2(b"NtQueryInformationProcess");

    let (ssn, addr) = unsafe { resolve(&ENTRY, HASH) }
        .map_err(|_| "resolve")?;

    let mut pbi = [0u8; 48];
    let mut ret_len: u32 = 0;

    let status = unsafe {
        do_syscall5(
            hproc,
            PROCESS_BASIC_INFORMATION as usize,
            pbi.as_mut_ptr() as usize,
            pbi.len(),
            &mut ret_len as *mut u32 as usize,
            ssn,
            addr,
        )
    };

    if status != STATUS_SUCCESS {
        unsafe { let _ = close_handle(hproc); };
        return Err("query failed");
    }

    // PROCESS_BASIC_INFORMATION (x64): ExitStatus(8), PebBaseAddress(*void @ +8)
    let peb_addr = unsafe { core::ptr::read_unaligned(pbi.as_ptr().add(8) as *const usize) };
    if peb_addr == 0 {
        unsafe { let _ = close_handle(hproc); };
        return Err("PEB address is null");
    }

    // Read PEB (first 64 bytes)
    let mut peb = [0u8; 64];
    if read_remote(hproc, peb_addr, &mut peb).is_err() {
        unsafe { let _ = close_handle(hproc); };
        return Err("peb read failed");
    }

    // PEB+0x18 = Ldr (PEB_LDR_DATA*)
    let ldr_addr = unsafe { core::ptr::read_unaligned(peb.as_ptr().add(0x18) as *const usize) };
    if ldr_addr == 0 {
        unsafe { let _ = close_handle(hproc); };
        return Err("LDR address is null");
    }

    // PEB_LDR_DATA+0x10 = InLoadOrderModuleList (LIST_ENTRY)
    let mut ldr_data = [0u8; 64];
    if read_remote(hproc, ldr_addr, &mut ldr_data).is_err() {
        unsafe { let _ = close_handle(hproc); };
        return Err("ldr read failed");
    }
    let list_head = unsafe { core::ptr::read_unaligned(ldr_data.as_ptr().add(0x10) as *const usize) };
    let list_head_addr = ldr_addr + 0x10;

    let mut flink = list_head;
    let mut iter_guard = 0usize;
    loop {
        if flink == 0 || flink == list_head_addr { break; }
        iter_guard += 1;
        if iter_guard > 1024 { break; } // safety: real proc has <500 modules

        // Read LDR entry (160 bytes)
        let entry_addr = flink;
        let mut entry = [0u8; 160];
        if read_remote(hproc, entry_addr, &mut entry).is_err() { break; }

        let dll_base = unsafe { core::ptr::read_unaligned(entry.as_ptr().add(48) as *const usize) };
        let size_of_image = unsafe { core::ptr::read_unaligned(entry.as_ptr().add(64) as *const u32) };

        let name_len = unsafe { core::ptr::read_unaligned(entry.as_ptr().add(88) as *const u16) } as usize / 2;
        let name_buf_ptr = unsafe { core::ptr::read_unaligned(entry.as_ptr().add(96) as *const usize) };

        let name = if name_buf_ptr != 0 && name_len > 0 && name_len <= 64 {
            let mut w = [0u16; 64];
            let mut nbuf = [0u8; 128];
            let n = name_len.min(64);
            let read_size = n * 2;
            if read_remote(hproc, name_buf_ptr, &mut nbuf[..read_size]).is_ok() {
                for k in 0..n {
                    w[k] = u16::from_le_bytes([nbuf[k*2], nbuf[k*2+1]]);
                }
            }
            wide_to_str(w.as_ptr(), n)
        } else {
            wide_to_str(core::ptr::null(), 0)
        };

        println!("0x{:016x} {:<12} {}", dll_base, size_of_image, name);

        let next = unsafe { core::ptr::read_unaligned(entry.as_ptr() as *const usize) };
        if next == flink { break; }
        flink = next;
    }

    unsafe { let _ = close_handle(hproc); };
    Ok(())
}

fn read_remote(hproc: usize, addr: usize, buf: &mut [u8]) -> Result<(), &'static str> {
    let mut read: usize = 0;
    let rc = unsafe {
        read_process_memory(hproc, addr, buf.as_mut_ptr(), buf.len(), &mut read)
    }.map_err(|_| "resolve")?;
    if rc == 0 { return Err("read failed"); }
    Ok(())
}

unsafe fn get_current_pid() -> u32 {
    // TEB+0x40 = ClientId.UniqueProcessId on x64
    let teb: *const u8;
    unsafe {
        core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb, options(nostack, preserves_flags));
        core::ptr::read_unaligned(teb.add(0x40) as *const u32)
    }
}

fn wide_to_str(ptr: *const u16, max: usize) -> WStr {
    let mut s = WStr::new();
    if ptr.is_null() {
        for b in b"?" { s.push(*b); }
        return s;
    }
    for i in 0..max.min(64) {
        let wc = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if wc == 0 { break; }
        s.push(if wc < 128 { wc as u8 } else { b'?' });
    }
    s
}

struct WStr { buf: [u8; 64], len: usize }
impl WStr {
    fn new() -> Self { Self { buf: [0u8; 64], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for WStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
