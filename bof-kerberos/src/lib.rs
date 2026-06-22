// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//! Kerberos enumeration helpers — LDAP filters and UAC flag parsing.
#![cfg_attr(not(test), no_std)]

pub const UAC_DONT_REQUIRE_PREAUTH: u32 = 0x400000;
pub const UAC_TRUSTED_FOR_DELEGATION: u32 = 0x80000;

pub const FILTER_ASREP: &[u8] =
    b"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
pub const FILTER_CONSTRAINED: &[u8] =
    b"(msDS-AllowedToDelegateTo=*)";
pub const FILTER_UNCONSTRAINED: &[u8] =
    b"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))";

/// Parse ASCII decimal UAC value to u32.
pub fn parse_uac(val: &[u8]) -> u32 {
    let mut n: u32 = 0;
    for &b in val {
        if b >= b'0' && b <= b'9' {
            n = n.wrapping_mul(10).wrapping_add((b - b'0') as u32);
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uac_basic() {
        assert_eq!(parse_uac(b"4194304"), UAC_DONT_REQUIRE_PREAUTH);
        assert_eq!(parse_uac(b"524288"), UAC_TRUSTED_FOR_DELEGATION);
        assert_eq!(parse_uac(b"512"), 512);
    }
}
