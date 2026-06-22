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

dfr_fn!(
    ldap_first_entry(ld: *mut u8, result: *mut u8) -> *mut u8,
    module = "wldap32.dll",
    api    = "ldap_first_entry"
);

dfr_fn!(
    ldap_next_entry(ld: *mut u8, entry: *mut u8) -> *mut u8,
    module = "wldap32.dll",
    api    = "ldap_next_entry"
);

dfr_fn!(
    ldap_get_dn_a(ld: *mut u8, entry: *mut u8) -> *mut i8,
    module = "wldap32.dll",
    api    = "ldap_get_dn"
);

dfr_fn!(
    ldap_get_values_a(ld: *mut u8, entry: *mut u8, attr: *const i8) -> *mut *mut i8,
    module = "wldap32.dll",
    api    = "ldap_get_values"
);

dfr_fn!(
    ldap_value_free_a(vals: *mut *mut i8) -> u32,
    module = "wldap32.dll",
    api    = "ldap_value_free"
);

dfr_fn!(
    ldap_memfree_a(ptr: *mut i8) -> u32,
    module = "wldap32.dll",
    api    = "ldap_memfree"
);

dfr_fn!(
    ldap_msgfree(msg: *mut u8) -> u32,
    module = "wldap32.dll",
    api    = "ldap_msgfree"
);

dfr_fn!(
    ldap_search_s_a(
        ld: *mut u8,
        base: *const i8,
        scope: u32,
        filter: *const i8,
        attrs: *mut *mut i8,
        attrs_only: u32,
        res: *mut *mut u8,
    ) -> u32,
    module = "wldap32.dll",
    api    = "ldap_search_s"
);
