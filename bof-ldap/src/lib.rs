// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
#![cfg_attr(not(test), no_std)]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

pub mod filter;
#[cfg(target_os = "windows")]
pub mod dfr;
#[cfg(target_os = "windows")]
pub mod conn;
#[cfg(target_os = "windows")]
pub use conn::{LdapHandle, connect_default_dc, bind_current_user};

#[cfg(target_os = "windows")]
pub mod entry;
#[cfg(target_os = "windows")]
pub use entry::LdapEntry;

#[derive(Debug, Clone, Copy)]
pub enum LdapErr {
    Init,
    Bind,
    Search,
    Paged,
    NoEntries,
}
