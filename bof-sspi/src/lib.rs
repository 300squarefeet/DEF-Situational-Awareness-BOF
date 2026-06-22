// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
#![cfg_attr(not(test), no_std)]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

#[cfg(target_os = "windows")]
pub mod dfr;

#[derive(Debug, Clone, Copy)]
pub enum SspiErr {
    AcquireCreds,
    InitCtx,
    NoOutputToken,
}
