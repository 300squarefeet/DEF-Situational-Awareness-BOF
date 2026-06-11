// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! no_std string conversion helpers. Buffer-based to avoid heap allocs on
//! hot paths inside BOFs.

/// Copy `src` ASCII bytes into `dst` as wide chars + NUL terminator.
/// Returns chars written (not counting NUL). Truncates if `dst` is too small.
pub fn ascii_to_wide_buf(src: &[u8], dst: &mut [u16]) -> usize {
    if dst.is_empty() { return 0; }
    let mut i = 0;
    while i < src.len() && i + 1 < dst.len() {
        dst[i] = src[i] as u16;
        i += 1;
    }
    dst[i] = 0;
    i
}

/// Copy `src` wide chars into `dst` as ASCII. Stops at first NUL in `src`.
/// Non-ASCII codepoints (>= 0x80) become `?`. Returns bytes written.
pub fn wide_to_ascii_buf(src: &[u16], dst: &mut [u8]) -> usize {
    if dst.is_empty() { return 0; }
    let mut i = 0;
    while i < src.len() && i + 1 < dst.len() {
        let c = src[i];
        if c == 0 { break; }
        dst[i] = if c < 128 { c as u8 } else { b'?' };
        i += 1;
    }
    dst[i] = 0;
    i
}
