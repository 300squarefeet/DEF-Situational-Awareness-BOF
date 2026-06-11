// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! Compile-time string XOR encryption. Decrypts on-stack at use site, never
//! stored as plaintext in `.rdata`. Use `obf!("…")` instead of bare string
//! literals for any sensitive name (API, registry path, CLSID guid string).

pub use obfstr::obfstr as obf_str;

#[macro_export]
macro_rules! obf {
    ($lit:literal) => { $crate::obf::obf_str!($lit) };
}
