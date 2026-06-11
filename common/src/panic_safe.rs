// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! Panic-safety primitives. The rustbof template installs a panic handler that
//! loops forever (no unwinding ever generated under `panic = "abort"`), so a
//! panic hangs the BOF thread rather than crashing Beacon. We still want zero
//! panics: `try_catch!` exists to keep `?` propagation localized and explicit.

/// Identity wrapper for `Result`-returning expressions. Exists as documentation
/// and a chokepoint where we could later add logging/metrics around the
/// fallible call without touching every call site.
#[macro_export]
macro_rules! try_catch {
    ($e:expr) => { ($e) };
}
