// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! DNS query via DnsQuery_A.
//! Args: <name> [type=A]
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::string::String;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1018",     name: "Remote System Discovery",                          tactic: "Discovery" },
    Technique { id: "T1016.001", name: "System Network Configuration Discovery: Internet", tactic: "Discovery" },
];

// DNS record types
const DNS_TYPE_A:    u16 = 1;
const DNS_TYPE_NS:   u16 = 2;
const DNS_TYPE_PTR:  u16 = 12;
const DNS_TYPE_MX:   u16 = 15;
const DNS_TYPE_TXT:  u16 = 16;
const DNS_TYPE_AAAA: u16 = 28;

const DNS_QUERY_STANDARD: u32 = 0;

#[repr(C)]
struct DnsRecord {
    p_next: *mut DnsRecord,
    p_name: *mut u16,
    r#type: u16,
    data_length: u16,
    flags: u32,
    ttl: u32,
    reserved: u32,
    // union data — we only read the first u32 (IPv4 for A records)
    data: [u8; 64],
}

dfr_fn!(
    dns_query_a(
        p_dns_name: *const i8,
        w_type: u16,
        options: u32,
        p_extra: *mut core::ffi::c_void,
        pp_query_results: *mut *mut DnsRecord,
        pp_message: *mut *mut core::ffi::c_void,
    ) -> i32,
    module = "dnsapi.dll",
    api    = "DnsQuery_A"
);

dfr_fn!(
    dns_record_list_free(p_record_list: *mut DnsRecord, free_type: u32) -> (),
    module = "dnsapi.dll",
    api    = "DnsRecordListFree"
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
    let name_s  = String::from(parser.get_str());
    let type_s  = String::from(parser.get_str());
    if name_s.is_empty() {
        return Err("usage: nslookup <name> [type=A]");
    }

    let qtype = if type_s.is_empty() {
        DNS_TYPE_A
    } else {
        parse_dns_type(type_s.as_str())
    };

    // Build NUL-terminated name buffer
    let mut name_buf = [0u8; 256];
    let nlen = name_s.len().min(255);
    name_buf[..nlen].copy_from_slice(&name_s.as_bytes()[..nlen]);

    let mut results: *mut DnsRecord = core::ptr::null_mut();
    let rc = unsafe {
        dns_query_a(
            name_buf.as_ptr() as *const i8,
            qtype,
            DNS_QUERY_STANDARD,
            core::ptr::null_mut(),
            &mut results,
            core::ptr::null_mut(),
        )
    }.map_err(|_| "query failed")?;

    if rc != 0 {
        println!("[!] query failed (code {})", rc);
        return Ok(());
    }

    if results.is_null() {
        println!("[*] no results");
        return Ok(());
    }

    println!("DNS results for: {}", name_s.as_str());
    println!("{}", "--------------------------------------------");

    let mut cur = results;
    while !cur.is_null() {
        let rec = unsafe { &*cur };
        let rtype = rec.r#type;
        match rtype {
            1 => {
                // A record — IPv4 in data[0..4]
                let ip: [u8; 4] = [rec.data[0], rec.data[1], rec.data[2], rec.data[3]];
                println!("  A     {}.{}.{}.{}  (TTL {})", ip[0], ip[1], ip[2], ip[3], rec.ttl);
            }
            28 => {
                println!("  AAAA  [IPv6]  (TTL {})", rec.ttl);
            }
            _ => {
                println!("  type={}  (TTL {})", rtype, rec.ttl);
            }
        }
        cur = rec.p_next;
    }

    unsafe { let _ = dns_record_list_free(results, 1); };
    Ok(())
}

fn parse_dns_type(s: &str) -> u16 {
    let b = s.as_bytes();
    if b.eq_ignore_ascii_case(b"A")    { return DNS_TYPE_A; }
    if b.eq_ignore_ascii_case(b"AAAA") { return DNS_TYPE_AAAA; }
    if b.eq_ignore_ascii_case(b"MX")   { return DNS_TYPE_MX; }
    if b.eq_ignore_ascii_case(b"NS")   { return DNS_TYPE_NS; }
    if b.eq_ignore_ascii_case(b"TXT")  { return DNS_TYPE_TXT; }
    if b.eq_ignore_ascii_case(b"PTR")  { return DNS_TYPE_PTR; }
    // try numeric
    let mut v: u16 = 0;
    for c in b { if c.is_ascii_digit() { v = v.wrapping_mul(10).wrapping_add((c - b'0') as u16); } else { return DNS_TYPE_A; } }
    if v == 0 { DNS_TYPE_A } else { v }
}
