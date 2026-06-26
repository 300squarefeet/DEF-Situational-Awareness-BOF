// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! AV/EDR enumeration via Service Control Manager — Phase 4 OperatorsKit.
//! Checks well-known AV/EDR service names via OpenServiceW without spawning
//! wmic.exe or any child process. All service names decrypted on-stack.
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1518.001", name: "Security Software Discovery", tactic: "Discovery" },
];

// Service access / state constants
const SC_MANAGER_CONNECT:   u32 = 0x0001;
const SC_MANAGER_ENUMERATE: u32 = 0x0004;
const SERVICE_QUERY_STATUS: u32 = 0x0004;

dfr_fn!(
    open_sc_manager_w(machine: *const u16, db: *const u16, access: u32) -> usize,
    module = "advapi32.dll",
    api    = "OpenSCManagerW"
);

dfr_fn!(
    open_service_w(scm: usize, svc_name: *const u16, access: u32) -> usize,
    module = "advapi32.dll",
    api    = "OpenServiceW"
);

dfr_fn!(
    query_service_status(svc: usize, status: *mut ServiceStatus) -> i32,
    module = "advapi32.dll",
    api    = "QueryServiceStatus"
);

dfr_fn!(
    close_service_handle(h: usize) -> i32,
    module = "advapi32.dll",
    api    = "CloseServiceHandle"
);

#[repr(C)]
struct ServiceStatus {
    service_type:             u32,
    current_state:            u32,
    controls_accepted:        u32,
    win32_exit_code:          u32,
    service_specific_exit:    u32,
    check_point:              u32,
    wait_hint:                u32,
}

impl ServiceStatus {
    fn new() -> Self {
        Self {
            service_type: 0, current_state: 0, controls_accepted: 0,
            win32_exit_code: 0, service_specific_exit: 0,
            check_point: 0, wait_hint: 0,
        }
    }
}

fn state_str(state: u32) -> &'static str {
    match state {
        1 => "STOPPED",
        2 => "START_PENDING",
        3 => "STOP_PENDING",
        4 => "RUNNING",
        5 => "CONTINUE_PENDING",
        6 => "PAUSE_PENDING",
        7 => "PAUSED",
        _ => "UNKNOWN",
    }
}

/// Encode an ASCII service name as inline wide chars on the stack.
/// Returns a 64-wide-char buffer and the length (including NUL).
fn to_wide_64(s: &[u8]) -> ([u16; 64], usize) {
    let mut buf = [0u16; 64];
    let n = s.len().min(63);
    for (i, &b) in s[..n].iter().enumerate() {
        buf[i] = b as u16;
    }
    buf[n] = 0;
    (buf, n + 1)
}

/// Try to open the named service and report state.
/// Uses obf!() to decrypt the literal name only on-stack — never in .rdata.
fn probe_service(scm: usize, name_bytes: &[u8], label: &str) {
    let (wide, _) = to_wide_64(name_bytes);
    let h = match unsafe { open_service_w(scm, wide.as_ptr(), SERVICE_QUERY_STATUS) } {
        Ok(h) if h != 0 => h,
        _ => return, // service not found — not an error
    };
    let mut status = ServiceStatus::new();
    let ok = unsafe { query_service_status(h, &mut status as *mut ServiceStatus) }
        .unwrap_or(0);
    unsafe { let _ = close_service_handle(h); };
    if ok != 0 {
        println!("[+] {:<30} {}", label, state_str(status.current_state));
    }
}

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    let scm = unsafe {
        open_sc_manager_w(
            core::ptr::null(),
            core::ptr::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE,
        )
    }.map_err(|_| "scm resolve failed")?;
    if scm == 0 {
        return Err("scm open failed");
    }

    println!("{:<30} {}", "Service", "State");
    println!("{}", "--------------------------------------------");

    // Microsoft Defender
    obf! { let s1  = "WinDefend";     }
    obf! { let s2  = "Sense";         }
    obf! { let s3  = "WdNisSvc";      }
    obf! { let s4  = "MsMpSvc";       }
    // ESET
    obf! { let s5  = "ekrn";          }
    obf! { let s6  = "EhttpSrv";      }
    // Avast / AVG
    obf! { let s7  = "avast! Antivirus"; }
    obf! { let s8  = "AvastNm";       }
    // Kaspersky
    obf! { let s9  = "avp";           }
    obf! { let s10 = "klif";          }
    obf! { let s11 = "KSecPkg";       }
    // Malwarebytes
    obf! { let s12 = "MBAMService";   }
    obf! { let s13 = "MBAMSwissArmy"; }
    // Bitdefender
    obf! { let s14 = "BdServiceHost"; }
    // CrowdStrike Falcon
    obf! { let s15 = "csagent";       }
    // SentinelOne
    obf! { let s16 = "SentinelAgent"; }
    // Cylance
    obf! { let s17 = "Cylance";       }
    // Carbon Black
    obf! { let s18 = "CarbonBlack";   }
    // Sophos
    obf! { let s19 = "SAVService";    }
    // Trend Micro
    obf! { let s20 = "TmPfw";         }

    probe_service(scm, s1.as_bytes(),  s1);
    probe_service(scm, s2.as_bytes(),  s2);
    probe_service(scm, s3.as_bytes(),  s3);
    probe_service(scm, s4.as_bytes(),  s4);
    probe_service(scm, s5.as_bytes(),  s5);
    probe_service(scm, s6.as_bytes(),  s6);
    probe_service(scm, s7.as_bytes(),  s7);
    probe_service(scm, s8.as_bytes(),  s8);
    probe_service(scm, s9.as_bytes(),  s9);
    probe_service(scm, s10.as_bytes(), s10);
    probe_service(scm, s11.as_bytes(), s11);
    probe_service(scm, s12.as_bytes(), s12);
    probe_service(scm, s13.as_bytes(), s13);
    probe_service(scm, s14.as_bytes(), s14);
    probe_service(scm, s15.as_bytes(), s15);
    probe_service(scm, s16.as_bytes(), s16);
    probe_service(scm, s17.as_bytes(), s17);
    probe_service(scm, s18.as_bytes(), s18);
    probe_service(scm, s19.as_bytes(), s19);
    probe_service(scm, s20.as_bytes(), s20);

    unsafe { let _ = close_service_handle(scm); };
    Ok(())
}
