// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
// wldap32.dll ANSI symbols resolved via djb2 (matches existing repo pattern).
use common::dfr_fn;

dfr_fn!(
    ldap_init_a(hostname: *const i8, port_number: u32) -> *mut u8,
    module = "wldap32.dll",
    api    = "ldap_init"
);

dfr_fn!(
    ldap_bind_s_a(
        ld: *mut u8,
        dn: *const i8,
        cred: *const i8,
        method: u32,
    ) -> u32,
    module = "wldap32.dll",
    api    = "ldap_bind_s"
);

dfr_fn!(
    ldap_unbind_s_a(ld: *mut u8) -> u32,
    module = "wldap32.dll",
    api    = "ldap_unbind_s"
);
