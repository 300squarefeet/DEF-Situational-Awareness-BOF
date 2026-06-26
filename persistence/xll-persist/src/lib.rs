// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//! xll-persist — Excel XLL add-in persistence (HKCU OPEN + XLSTART).
//! MITRE ATT&CK: T1137.006

#![cfg_attr(not(test), no_std)]
#![cfg_attr(all(not(test), target_os = "windows"), no_main)]

extern crate alloc;

pub mod args;
pub mod xlstart;
