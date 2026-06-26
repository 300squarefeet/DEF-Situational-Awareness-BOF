// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//! xlstart — XLSTART path / copy / basename helpers.

pub fn basename(path: &str) -> &str {
    let trimmed = path.trim_end_matches(['\\', '/']);
    let i = trimmed.rfind(['\\', '/']).map(|i| i + 1).unwrap_or(0);
    &trimmed[i..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_unc() {
        assert_eq!(basename("\\\\srv\\share\\evil.xll"), "evil.xll");
    }

    #[test]
    fn basename_drive() {
        assert_eq!(basename("C:\\dir\\evil.xll"), "evil.xll");
    }

    #[test]
    fn basename_trailing_slash() {
        assert_eq!(basename("C:\\dir\\evil.xll\\"), "evil.xll");
    }

    #[test]
    fn basename_no_separator() {
        assert_eq!(basename("evil.xll"), "evil.xll");
    }

    #[test]
    fn basename_empty() {
        assert_eq!(basename(""), "");
    }
}
