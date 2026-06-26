// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
];

dfr_fn!(
    global_memory_status_ex(lp_buffer: *mut u8) -> i32,
    module = "kernel32.dll",
    api    = "GlobalMemoryStatusEx"
);

dfr_fn!(
    get_system_info(lp_system_info: *mut u8) -> (),
    module = "kernel32.dll",
    api    = "GetSystemInfo"
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
    // MEMORYSTATUSEX: 64 bytes total, dwLength must be set to 64 before calling
    let mut mem_buf = [0u8; 64];
    unsafe { core::ptr::write_unaligned(mem_buf.as_mut_ptr() as *mut u32, 64u32) };
    let _ = unsafe { global_memory_status_ex(mem_buf.as_mut_ptr()) }.unwrap_or(0);

    // dwLength  @ 0  (u32)
    // dwMemoryLoad @ 4 (u32)
    // ullTotalPhys @ 8 (u64)
    // ullAvailPhys @ 16 (u64)
    // ullTotalPageFile @ 24 (u64)
    // ullAvailPageFile @ 32 (u64)
    // ullTotalVirtual @ 40 (u64)
    // ullAvailVirtual @ 48 (u64)
    let load       = unsafe { core::ptr::read_unaligned(mem_buf.as_ptr().add(4)  as *const u32) };
    let total_phys = unsafe { core::ptr::read_unaligned(mem_buf.as_ptr().add(8)  as *const u64) };
    let avail_phys = unsafe { core::ptr::read_unaligned(mem_buf.as_ptr().add(16) as *const u64) };
    let total_page = unsafe { core::ptr::read_unaligned(mem_buf.as_ptr().add(24) as *const u64) };
    let avail_page = unsafe { core::ptr::read_unaligned(mem_buf.as_ptr().add(32) as *const u64) };

    println!("Memory:");
    println!("  Load         : {}%", load);
    println!("  Total Phys   : {} MB", total_phys / 1_048_576);
    println!("  Avail Phys   : {} MB", avail_phys / 1_048_576);
    println!("  Total PageFile: {} MB", total_page / 1_048_576);
    println!("  Avail PageFile: {} MB", avail_page / 1_048_576);

    // SYSTEM_INFO: 48 bytes
    // wProcessorArchitecture @ 0 (u16)
    // dwPageSize @ 4 (u32)
    // lpMinimumApplicationAddress @ 8 (*mut c_void, usize)
    // lpMaximumApplicationAddress @ 16 (*mut c_void, usize)
    // dwActiveProcessorMask @ 24 (usize)
    // dwNumberOfProcessors @ 32 (u32)
    // dwProcessorType @ 36 (u32)
    let mut sys_buf = [0u8; 48];
    let _ = unsafe { get_system_info(sys_buf.as_mut_ptr()) };
    let arch      = unsafe { core::ptr::read_unaligned(sys_buf.as_ptr().add(0)  as *const u16) };
    let page_size = unsafe { core::ptr::read_unaligned(sys_buf.as_ptr().add(4)  as *const u32) };
    let num_cpus  = unsafe { core::ptr::read_unaligned(sys_buf.as_ptr().add(32) as *const u32) };
    let cpu_type  = unsafe { core::ptr::read_unaligned(sys_buf.as_ptr().add(36) as *const u32) };

    println!("CPU:");
    println!("  Processors   : {}", num_cpus);
    println!("  Architecture : {}", arch_name(arch));
    println!("  Processor Type: {}", cpu_type);
    println!("  Page Size    : {} bytes", page_size);

    Ok(())
}

fn arch_name(arch: u16) -> &'static str {
    match arch {
        0     => "x86",
        5     => "ARM",
        6     => "IA-64",
        9     => "x64",
        12    => "ARM64",
        0xFFFF => "Unknown",
        _     => "Other",
    }
}
