// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
#![cfg_attr(not(test), no_std)]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

pub mod filter;

#[derive(Debug, Clone, Copy)]
pub enum LdapErr {
    Init,
    Bind,
    Search,
    Paged,
    NoEntries,
}
