// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//! dfr — advapi32 / kernel32 / shell32 declarations.
//!
//! `dfr_fn!` produces functions returning `Result<T, &'static str>`. Call
//! sites must use match or `?` to extract; cleanup calls discard via
//! `let _ = unsafe { ... }`.
#![allow(non_snake_case)]

use common::dfr_fn;

pub const HKEY_CURRENT_USER: usize = 0x8000_0001;
pub const KEY_READ: u32        = 0x20019;
pub const KEY_WRITE: u32       = 0x20006;
pub const KEY_ALL_ACCESS: u32  = 0xF003F;
pub const REG_SZ: u32          = 1;
pub const ERROR_SUCCESS: u32   = 0;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;
pub const CSIDL_APPDATA: u32   = 0x001A;
pub const MAX_PATH_BYTES: usize = 260;
pub const INVALID_HANDLE_VALUE: usize = !0;
pub const ERROR_ALREADY_EXISTS: u32 = 183;

#[repr(C)]
pub struct FILETIME { pub dw_low: u32, pub dw_high: u32 }

#[repr(C)]
pub struct WIN32_FIND_DATAA {
    pub dw_file_attributes: u32,
    pub ft_creation_time: FILETIME,
    pub ft_last_access_time: FILETIME,
    pub ft_last_write_time: FILETIME,
    pub n_file_size_high: u32,
    pub n_file_size_low: u32,
    pub dw_reserved_0: u32,
    pub dw_reserved_1: u32,
    pub c_file_name: [u8; 260],
    pub c_alternate_file_name: [u8; 14],
    pub dw_file_type: u32,
    pub dw_creator_type: u32,
    pub w_finder_flags: u16,
}

dfr_fn!(
    RegOpenKeyExA(h_key: usize, sub_key: *const i8, options: u32, sam_desired: u32, result: *mut usize) -> u32,
    module = "advapi32.dll", api = "RegOpenKeyExA"
);

dfr_fn!(
    RegCloseKey(h_key: usize) -> u32,
    module = "advapi32.dll", api = "RegCloseKey"
);

dfr_fn!(
    RegEnumKeyExA(
        h_key: usize, index: u32, name: *mut i8, name_len: *mut u32,
        reserved: *mut u32, class_: *mut i8, class_len: *mut u32, last_write: *mut FILETIME
    ) -> u32,
    module = "advapi32.dll", api = "RegEnumKeyExA"
);

dfr_fn!(
    RegEnumValueA(
        h_key: usize, index: u32, name: *mut i8, name_len: *mut u32,
        reserved: *mut u32, type_: *mut u32, data: *mut u8, data_len: *mut u32
    ) -> u32,
    module = "advapi32.dll", api = "RegEnumValueA"
);

dfr_fn!(
    RegQueryValueExA(
        h_key: usize, value_name: *const i8, reserved: *mut u32,
        type_: *mut u32, data: *mut u8, data_len: *mut u32
    ) -> u32,
    module = "advapi32.dll", api = "RegQueryValueExA"
);

dfr_fn!(
    RegSetValueExA(
        h_key: usize, value_name: *const i8, reserved: u32,
        type_: u32, data: *const u8, data_len: u32
    ) -> u32,
    module = "advapi32.dll", api = "RegSetValueExA"
);

dfr_fn!(
    RegDeleteValueA(h_key: usize, value_name: *const i8) -> u32,
    module = "advapi32.dll", api = "RegDeleteValueA"
);

dfr_fn!(
    SHGetFolderPathA(h_wnd: usize, csidl: u32, h_token: usize, flags: u32, path: *mut u8) -> u32,
    module = "shell32.dll", api = "SHGetFolderPathA"
);

dfr_fn!(
    CopyFileA(src: *const i8, dst: *const i8, fail_if_exists: u32) -> u32,
    module = "kernel32.dll", api = "CopyFileA"
);

dfr_fn!(
    DeleteFileA(name: *const i8) -> u32,
    module = "kernel32.dll", api = "DeleteFileA"
);

dfr_fn!(
    CreateDirectoryA(name: *const i8, sec: *mut u8) -> u32,
    module = "kernel32.dll", api = "CreateDirectoryA"
);

dfr_fn!(
    FindFirstFileA(name: *const i8, data: *mut WIN32_FIND_DATAA) -> usize,
    module = "kernel32.dll", api = "FindFirstFileA"
);

dfr_fn!(
    FindNextFileA(h: usize, data: *mut WIN32_FIND_DATAA) -> u32,
    module = "kernel32.dll", api = "FindNextFileA"
);

dfr_fn!(
    FindClose(h: usize) -> u32,
    module = "kernel32.dll", api = "FindClose"
);

dfr_fn!(
    GetLastError() -> u32,
    module = "kernel32.dll", api = "GetLastError"
);
