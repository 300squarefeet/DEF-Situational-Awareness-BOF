// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Set Hidden + System file attributes to conceal a file on disk.
//!
//! Calls GetFileAttributesA, ORs in HIDDEN|SYSTEM, then SetFileAttributesA.
//!
//! Args: <filepath>
//!
//! MITRE ATT&CK: T1564.001 (Hide Artifacts: Hidden Files and Directories)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1564.001",
        name: "Hide Artifacts: Hidden Files and Directories",
        tactic: "Defense Evasion",
    },
];

const FILE_ATTRIBUTE_HIDDEN:             u32 = 0x0002;
const FILE_ATTRIBUTE_SYSTEM:             u32 = 0x0004;
const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x2000;
const INVALID_FILE_ATTRIBUTES:           u32 = 0xFFFF_FFFF;

dfr_fn!(
    get_file_attributes_a(lp_file_name: *const i8) -> u32,
    module = "kernel32.dll",
    api    = "GetFileAttributesA"
);

dfr_fn!(
    set_file_attributes_a(lp_file_name: *const i8, dw_file_attributes: u32) -> i32,
    module = "kernel32.dll",
    api    = "SetFileAttributesA"
);

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let filepath = String::from(parser.get_str());
    if filepath.is_empty() {
        return Err("usage: hide-file <filepath>");
    }
    if filepath.len() > 512 { return Err("path too long"); }

    // Build NUL-terminated C string on stack
    let mut path_cstr = [0i8; 516];
    for (i, b) in filepath.bytes().enumerate() {
        if i + 1 < path_cstr.len() { path_cstr[i] = b as i8; }
    }

    let attrs = unsafe {
        get_file_attributes_a(path_cstr.as_ptr())
    }.map_err(|_| "resolve failed")?;

    if attrs == INVALID_FILE_ATTRIBUTES {
        return Err("file not found");
    }

    let new_attrs = attrs
        | FILE_ATTRIBUTE_HIDDEN
        | FILE_ATTRIBUTE_SYSTEM
        | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

    let rc = unsafe {
        set_file_attributes_a(path_cstr.as_ptr(), new_attrs)
    }.map_err(|_| "resolve failed")?;

    if rc == 0 {
        return Err("attribute set failed");
    }

    println!("[+] file hidden: {}", filepath);
    Ok(())
}
