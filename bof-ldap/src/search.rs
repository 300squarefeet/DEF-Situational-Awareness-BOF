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

/// Perform a synchronous paged LDAP subtree search using RFC 2696 paged-results
/// control (OID 1.2.840.113556.1.4.319).  Loops until the server returns an
/// empty cookie.  Calls `on_entry` for every result entry across all pages.
pub fn search_paged<F: FnMut(&LdapEntry)>(
    h: &LdapHandle,
    base_cstr: *const i8,
    filter_cstr: *const i8,
    attrs: &mut [*mut i8],
    page_size: u32,
    mut on_entry: F,
) -> Result<(), LdapErr> {
    let mut cookie: *mut LdapBerVal = core::ptr::null_mut();

    loop {
        let mut page_ctrl: *mut LdapControl = core::ptr::null_mut();
        let mut server_controls: [*mut LdapControl; 2] = [core::ptr::null_mut(); 2];

        let rc = match unsafe {
            ldap_create_page_control(h.0, page_size, cookie, 1, &mut page_ctrl)
        } {
            Ok(c) => c,
            Err(_) => return Err(LdapErr::Paged),
        };
        if rc != LDAP_SUCCESS {
            return Err(LdapErr::Paged);
        }
        server_controls[0] = page_ctrl;

        let mut msg: *mut u8 = core::ptr::null_mut();
        let attr_ptr = if attrs.is_empty() {
            core::ptr::null_mut()
        } else {
            attrs.as_mut_ptr()
        };
        let rc = match unsafe {
            ldap_search_ext_s_a(
                h.0,
                base_cstr,
                LDAP_SCOPE_SUBTREE,
                filter_cstr,
                attr_ptr,
                0,
                server_controls.as_mut_ptr(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
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
            Err(_) => core::ptr::null_mut(),
        };
        while !entry_ptr.is_null() {
            let e = LdapEntry { ld: h.0, msg: entry_ptr };
            on_entry(&e);
            entry_ptr = match unsafe { ldap_next_entry(h.0, entry_ptr) } {
                Ok(p) => p,
                Err(_) => core::ptr::null_mut(),
            };
        }

        let mut returned_controls: *mut *mut LdapControl = core::ptr::null_mut();
        let mut return_code: u32 = 0;
        let _ = unsafe {
            ldap_parse_result(
                h.0,
                msg,
                &mut return_code,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut returned_controls,
                0,
            )
        };

        let mut new_cookie: *mut LdapBerVal = core::ptr::null_mut();
        let mut total: u32 = 0;
        let _ = unsafe {
            ldap_parse_page_control(h.0, returned_controls, &mut total, &mut new_cookie)
        };
        if !returned_controls.is_null() {
            let _ = unsafe { ldap_controls_free(returned_controls) };
        }
        let _ = unsafe { ldap_msgfree(msg) };

        // Free the previous iteration's cookie before overwriting
        if !cookie.is_null() {
            let _ = unsafe { ber_bvfree(cookie) };
        }

        cookie = new_cookie;
        if cookie.is_null() || unsafe { (*cookie).bv_len } == 0 {
            if !cookie.is_null() {
                let _ = unsafe { ber_bvfree(cookie) };
            }
            break;
        }
    }
    Ok(())
}
