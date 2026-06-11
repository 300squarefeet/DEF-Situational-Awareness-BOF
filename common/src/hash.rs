// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! Compile-time string hashing for API/module resolution.
//! djb2 is preferred over fnv1a here for its lower collision rate on short PE
//! export names per measurement on ntdll exports (Dani).

#[inline]
pub const fn djb2(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < bytes.len() {
        // hash * 33 + c
        hash = hash.wrapping_mul(33).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    hash
}

#[inline]
pub const fn djb2_case_insensitive(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < bytes.len() {
        let mut c = bytes[i];
        if c >= b'A' && c <= b'Z' { c += 32; }  // ASCII lowercase
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
        i += 1;
    }
    hash
}

/// Constant-evaluation macro: `api_hash!("NtOpenProcessToken")` → `u32`.
#[macro_export]
macro_rules! api_hash {
    ($s:literal) => { $crate::hash::djb2($s.as_bytes()) };
}

/// Case-insensitive variant for module names (the loader stores them in mixed case).
#[macro_export]
macro_rules! module_hash {
    ($s:literal) => { $crate::hash::djb2_case_insensitive($s.as_bytes()) };
}
