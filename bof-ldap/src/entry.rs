// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT

extern crate alloc;
use alloc::vec::Vec;
use crate::dfr::*;

/// A single LDAP message entry. Does not own the underlying LDAP memory;
/// lifetime is tied to the search result message freed at the search level
/// via ldap_msgfree.
pub struct LdapEntry {
    pub ld:  *mut u8,
    pub msg: *mut u8,
}

impl LdapEntry {
    /// Returns the DN of this entry as an owned byte vector (ANSI, no NUL).
    /// Returns an empty Vec on failure.
    pub fn dn(&self) -> Vec<u8> {
        let raw = match unsafe { ldap_get_dn_a(self.ld, self.msg) } {
            Ok(p) if !p.is_null() => p,
            _ => return Vec::new(),
        };
        let mut out = Vec::new();
        unsafe {
            let mut p = raw;
            while *p != 0 {
                out.push(*p as u8);
                p = p.add(1);
            }
            let _ = ldap_memfree_a(raw);
        }
        out
    }

    /// Returns all values for the given attribute (ANSI C-string pointer).
    /// Each value is returned as an owned byte vector (no NUL terminator).
    /// Returns an empty Vec on failure or when the attribute is absent.
    pub fn values(&self, attr_cstr: *const i8) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        let raw = match unsafe { ldap_get_values_a(self.ld, self.msg, attr_cstr) } {
            Ok(p) if !p.is_null() => p,
            _ => return result,
        };
        unsafe {
            let mut i = 0isize;
            loop {
                let p = *raw.offset(i);
                if p.is_null() {
                    break;
                }
                let mut v = Vec::new();
                let mut q = p;
                while *q != 0 {
                    v.push(*q as u8);
                    q = q.add(1);
                }
                result.push(v);
                i += 1;
            }
            let _ = ldap_value_free_a(raw);
        }
        result
    }
}
