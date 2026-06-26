// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: shared OPSEC primitives
//
#![no_std]
#![allow(clippy::missing_safety_doc)]
#![cfg_attr(target_os = "windows", feature(naked_functions))]

extern crate alloc;

pub mod credit;
pub mod hash;
pub mod mitre;
pub mod panic_safe;
pub mod str_util;
pub mod obf;
pub mod com;

#[cfg(target_arch = "x86_64")]
pub mod syscalls;
#[cfg(target_arch = "x86_64")]
pub mod token;
#[cfg(target_arch = "x86_64")]
pub mod dfr;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub mod evasion;
