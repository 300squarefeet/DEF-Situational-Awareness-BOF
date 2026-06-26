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

#[cfg(target_os = "windows")]
mod win {
    extern crate alloc;
    use alloc::vec::Vec;
    use alloc::string::String;
    use core::ptr::null_mut;
    use crate::dfr::*;
    use super::{slot_name, find_first_free_slot_from};

    pub fn scan_present(h: usize) -> [bool; 100] {
        let mut present = [false; 100];
        for i in 0..100 {
            let name = slot_name(i);
            let cstr = cstr(&name);
            let mut size: u32 = 0;
            let rc = match unsafe {
                RegQueryValueExA(h, cstr.as_ptr() as *const i8, null_mut(), null_mut(), null_mut(), &mut size)
            } { Ok(c) => c, Err(_) => continue };
            present[i] = rc == ERROR_SUCCESS;
        }
        present
    }

    pub fn write(h: usize, slot_idx: usize, value: &str) -> Result<(), ()> {
        let name = slot_name(slot_idx);
        let name_c = cstr(&name);
        let val_c = cstr(value);
        let rc = match unsafe {
            RegSetValueExA(
                h, name_c.as_ptr() as *const i8, 0, REG_SZ,
                val_c.as_ptr(), val_c.len() as u32,
            )
        } { Ok(c) => c, Err(_) => return Err(()) };
        if rc != ERROR_SUCCESS { return Err(()); }
        Ok(())
    }

    pub fn read(h: usize, slot_idx: usize) -> Option<String> {
        let name = slot_name(slot_idx);
        let name_c = cstr(&name);
        let mut buf = [0u8; 1024];
        let mut size: u32 = buf.len() as u32;
        let rc = match unsafe {
            RegQueryValueExA(h, name_c.as_ptr() as *const i8, null_mut(), null_mut(), buf.as_mut_ptr(), &mut size)
        } { Ok(c) => c, Err(_) => return None };
        if rc != ERROR_SUCCESS { return None; }
        let end = (size as usize).min(buf.len());
        let trimmed = buf[..end].split(|b| *b == 0).next().unwrap_or(&[]);
        Some(String::from_utf8_lossy(trimmed).into_owned())
    }

    pub fn find_matching(h: usize, path: &str) -> Vec<usize> {
        let mut out = Vec::new();
        for i in 0..100 {
            if let Some(v) = read(h, i) {
                if v.contains(path) { out.push(i); }
            }
        }
        out
    }

    pub fn delete(h: usize, slot_idx: usize) -> Result<(), ()> {
        let name = slot_name(slot_idx);
        let name_c = cstr(&name);
        let rc = match unsafe { RegDeleteValueA(h, name_c.as_ptr() as *const i8) } {
            Ok(c) => c, Err(_) => return Err(()),
        };
        if rc != ERROR_SUCCESS { return Err(()); }
        Ok(())
    }

    pub fn first_free(h: usize) -> Option<usize> {
        find_first_free_slot_from(&scan_present(h))
    }

    fn cstr(s: &str) -> Vec<u8> {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        v
    }
}

#[cfg(target_os = "windows")]
pub use win::*;
