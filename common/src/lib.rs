// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: shared OPSEC primitives — by Dani
//
#![no_std]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

pub mod credit;
pub mod hash;
pub mod mitre;
pub mod panic_safe;
pub mod str_util;
pub mod obf;
pub mod dfr        { /* filled in Task 10 */ }
pub mod syscalls   { /* filled in Task 11 */ }
pub mod com        { /* filled in Task 12 */ }
pub mod token      { /* filled in Task 13 */ }
