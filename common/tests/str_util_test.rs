// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT

use common::str_util::{ascii_to_wide_buf, wide_to_ascii_buf};

#[test]
fn ascii_to_wide_basic() {
    let mut buf = [0u16; 16];
    let n = ascii_to_wide_buf(b"hello", &mut buf);
    assert_eq!(n, 5);
    assert_eq!(&buf[..6], &[b'h' as u16, b'e' as u16, b'l' as u16, b'l' as u16, b'o' as u16, 0]);
}

#[test]
fn ascii_to_wide_truncates_at_buf_minus_one() {
    let mut buf = [0u16; 4];   // 3 chars + NUL
    let n = ascii_to_wide_buf(b"hello", &mut buf);
    assert_eq!(n, 3);
    assert_eq!(buf[3], 0);
}

#[test]
fn wide_to_ascii_basic() {
    let wide: [u16; 6] = [b'h' as u16, b'i' as u16, 0x4e2d, b'!' as u16, 0, 0];
    let mut buf = [0u8; 16];
    let n = wide_to_ascii_buf(&wide, &mut buf);
    // 0x4e2d (中) is non-ASCII → emits '?'
    assert_eq!(&buf[..n], b"hi?!");
}
