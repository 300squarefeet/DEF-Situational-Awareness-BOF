// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//! reg_open — OPEN[N] slot CRUD.

extern crate alloc;
use alloc::string::String;
use alloc::format;

pub fn slot_name(idx: usize) -> String {
    if idx == 0 { String::from("OPEN") } else { format!("OPEN{}", idx) }
}

pub fn find_first_free_slot_from(present: &[bool]) -> Option<usize> {
    present.iter().position(|p| !p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_zero_is_open_no_suffix() {
        assert_eq!(slot_name(0), "OPEN");
    }

    #[test]
    fn slot_one_is_open1() {
        assert_eq!(slot_name(1), "OPEN1");
    }

    #[test]
    fn slot_ninety_nine_is_open99() {
        assert_eq!(slot_name(99), "OPEN99");
    }

    #[test]
    fn free_slot_finds_first_gap() {
        let v = [true, true, false, true, false];
        assert_eq!(find_first_free_slot_from(&v), Some(2));
    }

    #[test]
    fn free_slot_none_when_full() {
        let v = [true, true, true];
        assert_eq!(find_first_free_slot_from(&v), None);
    }

    #[test]
    fn free_slot_empty_returns_none() {
        assert_eq!(find_first_free_slot_from(&[]), None);
    }
}
