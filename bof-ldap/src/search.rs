// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT

use crate::{LdapErr, LdapEntry, conn::LdapHandle, dfr::*};

pub const LDAP_SCOPE_SUBTREE: u32 = 2;
pub const LDAP_SUCCESS: u32 = 0;

/// Perform a synchronous subtree LDAP search and call `on_entry` for each
/// result entry.  All Win32 calls go through `dfr_fn!`; no buffers are
/// allocated beyond the single result message chain returned by wldap32.
pub fn search_nopaged<F: FnMut(&LdapEntry)>(
    h: &LdapHandle,
    base_cstr: *const i8,
    filter_cstr: *const i8,
    attrs: &mut [*mut i8],
    mut on_entry: F,
) -> Result<(), LdapErr> {
    let mut msg: *mut u8 = core::ptr::null_mut();
    let attr_ptr = if attrs.is_empty() {
        core::ptr::null_mut()
    } else {
        attrs.as_mut_ptr()
    };

    let rc = match unsafe {
        ldap_search_s_a(
            h.0,
            base_cstr,
            LDAP_SCOPE_SUBTREE,
            filter_cstr,
            attr_ptr,
            0,
            &mut msg,
        )
    } {
        Ok(c) => c,
        Err(_) => return Err(LdapErr::Search),
    };
    if rc != LDAP_SUCCESS || msg.is_null() {
        return Err(LdapErr::Search);
    }

    let mut entry_ptr = match unsafe { ldap_first_entry(h.0, msg) } {
        Ok(p) => p,
        Err(_) => {
            let _ = unsafe { ldap_msgfree(msg) };
            return Err(LdapErr::NoEntries);
        }
    };

    while !entry_ptr.is_null() {
        let e = LdapEntry { ld: h.0, msg: entry_ptr };
        on_entry(&e);
        entry_ptr = match unsafe { ldap_next_entry(h.0, entry_ptr) } {
            Ok(p) => p,
            Err(_) => core::ptr::null_mut(),
        };
    }

    let _ = unsafe { ldap_msgfree(msg) };
    Ok(())
}
