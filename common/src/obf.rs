// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! Compile-time string XOR encryption. Decrypts on-stack at use site, never
//! stored as plaintext in `.rdata`. Use the macros below instead of bare
//! string literals for any sensitive name (API, registry path, CLSID guid
//! string, WQL query, etc.).
//!
//! All macros support the same forms as `obfstr`:
//!   - `obf!(let name = "...";)`   declares `name` in current scope
//!   - `obf!(name = "...")`        assigns to existing `let name;`
//!   - `obf!(buf <- "...")`        decrypts into caller-provided buffer
//!   - `obf!("...")`               returns temporary, use in same statement only
//!
//! Variants:
//!   - `obf!(...)`        — `&str`
//!   - `obf_cstr!(...)`   — `&CStr` from a `c"..."` literal
//!   - `obf_bytes!(...)`  — `&[u8]`

pub use obfstr;

#[macro_export]
macro_rules! obf {
    ($($t:tt)*) => { $crate::obf::obfstr::obfstr!($($t)*) };
}

#[macro_export]
macro_rules! obf_cstr {
    ($($t:tt)*) => { $crate::obf::obfstr::obfcstr!($($t)*) };
}

#[macro_export]
macro_rules! obf_bytes {
    ($($t:tt)*) => { $crate::obf::obfstr::obfbytes!($($t)*) };
}
