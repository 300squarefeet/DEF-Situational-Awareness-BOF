// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
use crate::{LdapErr, dfr::*};

pub const LDAP_PORT: u32 = 389;
pub const LDAP_AUTH_NEGOTIATE: u32 = 0x0486;
pub const LDAP_SUCCESS: u32 = 0;

pub struct LdapHandle(pub *mut u8);

impl Drop for LdapHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // Ignore resolution or call failure in Drop — nothing we can do.
            let _ = unsafe { ldap_unbind_s_a(self.0) };
            self.0 = core::ptr::null_mut();
        }
    }
}

pub fn connect_default_dc(host_cstr: *const i8, port: u32) -> Result<LdapHandle, LdapErr> {
    let h = unsafe { ldap_init_a(host_cstr, port) }
        .map_err(|_| LdapErr::Init)?;
    if h.is_null() {
        return Err(LdapErr::Init);
    }
    Ok(LdapHandle(h))
}

pub fn bind_current_user(h: &LdapHandle) -> Result<(), LdapErr> {
    let rc = unsafe {
        ldap_bind_s_a(
            h.0,
            core::ptr::null(),
            core::ptr::null(),
            LDAP_AUTH_NEGOTIATE,
        )
    }
    .map_err(|_| LdapErr::Bind)?;
    if rc != LDAP_SUCCESS {
        return Err(LdapErr::Bind);
    }
    Ok(())
}
