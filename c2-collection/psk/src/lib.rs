// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
// Original C: Outflank/C2-Tool-Collection — Psk/
//
//! `psk` — kernel-mode driver enumeration via indirect syscall.
//!
//! Calls NtQuerySystemInformation(SystemModuleInformation=11) to retrieve
//! the full list of loaded kernel modules. Each entry is parsed from the
//! RTL_PROCESS_MODULES structure and compared against a known EDR/AV driver
//! name list (obfuscated at compile time via obfstr). Matches are flagged
//! as [EDR/AV] in the output.
//!
//! MITRE: T1518.001 (Security Software Discovery), T1057 (Process Discovery)

#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::vec::Vec;
use rustbof::{println, eprintln};
use common::{mitre::Technique, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1518.001", name: "Security Software Discovery", tactic: "Discovery" },
    Technique { id: "T1057",     name: "Process Discovery",           tactic: "Discovery" },
];

// NtQuerySystemInformation info class for kernel modules
const SYSTEM_MODULE_INFORMATION: usize = 11;
const STATUS_SUCCESS:            i32   = 0;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;

// Precomputed hash — byte literal stays compile-time only
const HASH_NT_QUERY_SYSTEM_INFO: u32 = common::hash::djb2(b"NtQuerySystemInformation");

// RTL_PROCESS_MODULES layout (x64):
//   +0   NumberOfModules  ULONG
//   +8   Modules[0]       RTL_PROCESS_MODULE_INFORMATION (296 bytes each)
//
// RTL_PROCESS_MODULE_INFORMATION (296 bytes):
//   +0   Section                  HANDLE       (8)
//   +8   MappedBase               PVOID        (8)
//   +16  ImageBase                PVOID        (8)
//   +24  ImageSize                ULONG        (4)
//   +28  Flags                    ULONG        (4)
//   +32  LoadOrderIndex           USHORT       (2)
//   +34  InitOrderIndex           USHORT       (2)
//   +36  LoadCount                USHORT       (2)
//   +38  OffsetToFileName         USHORT       (2)  — byte offset into FullPathName
//   +40  FullPathName[256]        CHAR[256]    (256)
// Total: 8+8+8+4+4+2+2+2+2+256 = 296
const MODULE_ENTRY_SIZE: usize = 296;
const OFFSET_IMAGE_BASE:    usize = 16;
const OFFSET_IMAGE_SIZE:    usize = 24;
const OFFSET_OFFSET_TO_FILENAME: usize = 38; // u16: byte offset within FullPathName
const OFFSET_FULL_PATH:     usize = 40;
const FULL_PATH_LEN:        usize = 256;

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(())  => {},
        Err(e)  => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    use common::syscalls::{SyscallEntry, resolve, do_syscall4};

    static ENTRY: SyscallEntry = SyscallEntry::new();
    let (ssn, addr) = unsafe { resolve(&ENTRY, HASH_NT_QUERY_SYSTEM_INFO) }
        .map_err(|_| "resolve failed")?;

    // Grow buffer until NtQuerySystemInformation succeeds
    let mut size: u32 = 65536;
    let buf;
    loop {
        let mut v: Vec<u8> = alloc::vec![0u8; size as usize];
        let mut ret_len: u32 = 0;
        let status = unsafe {
            do_syscall4(
                SYSTEM_MODULE_INFORMATION,
                v.as_mut_ptr() as usize,
                size as usize,
                &mut ret_len as *mut u32 as usize,
                ssn, addr,
            )
        };
        if status == STATUS_SUCCESS {
            buf = v;
            break;
        } else if status == STATUS_INFO_LENGTH_MISMATCH {
            if size >= 64 * 1024 * 1024 {
                return Err("buf too large");
            }
            size = size.saturating_mul(2);
            continue;
        } else {
            return Err("query failed");
        }
    }

    if buf.len() < 8 { return Err("short buf"); }

    // NumberOfModules at offset 0
    let count = unsafe {
        core::ptr::read_unaligned(buf.as_ptr() as *const u32)
    } as usize;

    // Build EDR/AV driver name list — all obfuscated at compile time
    obf! { let d01 = "csagent.sys";          }
    obf! { let d02 = "elam.sys";             }
    obf! { let d03 = "mssec.sys";            }
    obf! { let d04 = "wdfilter.sys";         }
    obf! { let d05 = "klif.sys";             }
    obf! { let d06 = "klflt.sys";            }
    obf! { let d07 = "klhk.sys";             }
    obf! { let d08 = "klkbdflt.sys";         }
    obf! { let d09 = "atc.sys";              }
    obf! { let d10 = "atrsdfw.sys";          }
    obf! { let d11 = "eamonm.sys";           }
    obf! { let d12 = "ehdrv.sys";            }
    obf! { let d13 = "epfwwfp.sys";          }
    obf! { let d14 = "edrsensor.sys";        }
    obf! { let d15 = "sysmondrv.sys";        }
    obf! { let d16 = "mbamchameleon.sys";    }
    obf! { let d17 = "trustedinstaller.sys"; }
    obf! { let d18 = "carbonblackk.sys";     }
    obf! { let d19 = "cb.sys";               }
    obf! { let d20 = "cyverak.sys";          }
    obf! { let d21 = "cyprotectdrv.sys";     }
    obf! { let d22 = "sentinelone.sys";      }
    obf! { let d23 = "sentinelmonitor.sys";  }

    let edr_drivers: &[&str] = &[
        d01, d02, d03, d04, d05, d06, d07, d08, d09, d10,
        d11, d12, d13, d14, d15, d16, d17, d18, d19, d20,
        d21, d22, d23,
    ];

    println!("{:<18} {:<12} {}", "Base", "Size", "Name");
    println!("{}", "------------------------------------------------------------");

    let base_ptr = unsafe { buf.as_ptr().add(8) }; // skip NumberOfModules (ULONG at 0, padded to 8)

    for i in 0..count {
        let entry_off = i * MODULE_ENTRY_SIZE;
        if entry_off + MODULE_ENTRY_SIZE > buf.len() - 8 { break; }

        let ep = unsafe { base_ptr.add(entry_off) };

        let image_base = unsafe { core::ptr::read_unaligned(ep.add(OFFSET_IMAGE_BASE) as *const usize) };
        let image_size = unsafe { core::ptr::read_unaligned(ep.add(OFFSET_IMAGE_SIZE) as *const u32) };
        let name_off   = unsafe { core::ptr::read_unaligned(ep.add(OFFSET_OFFSET_TO_FILENAME) as *const u16) } as usize;

        // FullPathName is CHAR[256] starting at OFFSET_FULL_PATH
        let full_path_ptr = unsafe { ep.add(OFFSET_FULL_PATH) };

        // Extract just the filename portion (starting at name_off within FullPathName)
        let name_start = if name_off < FULL_PATH_LEN { name_off } else { 0 };
        let name_ptr = unsafe { full_path_ptr.add(name_start) };

        // Copy name into a local buf (null-terminate defensively)
        let mut nbuf = [0u8; 64];
        let available = (FULL_PATH_LEN - name_start).min(63);
        for j in 0..available {
            let c = unsafe { *name_ptr.add(j) };
            if c == 0 { break; }
            nbuf[j] = c;
        }
        let name_str = core::str::from_utf8(&nbuf[..cstr_len(&nbuf)]).unwrap_or("?");

        // Check for EDR/AV match (case-insensitive compare)
        let is_edr = edr_drivers.iter().any(|&d| icase_eq(name_str.as_bytes(), d.as_bytes()));
        let tag = if is_edr { "[EDR/AV]" } else { "" };

        println!("0x{:016x} {:<12} {} {}", image_base, image_size, name_str, tag);
    }

    println!("");
    println!("[*] {} kernel modules enumerated", count);

    Ok(())
}

/// Length of a null-terminated byte slice (cstr style).
fn cstr_len(s: &[u8]) -> usize {
    s.iter().position(|&b| b == 0).unwrap_or(s.len())
}

/// Case-insensitive ASCII byte-slice comparison.
fn icase_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b.iter()).all(|(&x, &y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}
