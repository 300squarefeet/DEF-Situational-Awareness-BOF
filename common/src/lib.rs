// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: shared OPSEC primitives — by Dani
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
pub mod dfr;
pub mod syscalls;
pub mod com;
pub mod token      { /* filled in Task 13 */ }
