// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! QueryServiceConfig2A SERVICE_CONFIG_TRIGGER_INFO — trigger count and types.
//! Args: <servicename>
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::string::String;
use alloc::vec::Vec;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1007", name: "System Service Discovery", tactic: "Discovery" },
];

const SC_MANAGER_CONNECT: u32        = 0x0001;
const SERVICE_QUERY_CONFIG: u32      = 0x0001;
const SERVICE_CONFIG_TRIGGER_INFO: u32 = 8;

// SERVICE_TRIGGER_TYPE values
const SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL: u32 = 1;
const SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY: u32  = 2;
const SERVICE_TRIGGER_TYPE_DOMAIN_JOIN: u32              = 3;
const SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT: u32      = 4;
const SERVICE_TRIGGER_TYPE_GROUP_POLICY: u32             = 5;
const SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT: u32         = 6;
const SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE: u32 = 7;
const SERVICE_TRIGGER_TYPE_CUSTOM: u32                   = 20;

dfr_fn!(
    open_sc_manager_a(
        lp_machine_name: *const i8,
        lp_database_name: *const i8,
        dw_desired_access: u32,
    ) -> *mut core::ffi::c_void,
    module = "advapi32.dll",
    api    = "OpenSCManagerA"
);

dfr_fn!(
    open_service_a(
        h_sc_manager: *mut core::ffi::c_void,
        lp_service_name: *const i8,
        dw_desired_access: u32,
    ) -> *mut core::ffi::c_void,
    module = "advapi32.dll",
    api    = "OpenServiceA"
);

dfr_fn!(
    query_service_config2_a(
        h_service: *mut core::ffi::c_void,
        dw_info_level: u32,
        lp_buffer: *mut u8,
        cb_buf_size: u32,
        pcb_bytes_needed: *mut u32,
    ) -> i32,
    module = "advapi32.dll",
    api    = "QueryServiceConfig2A"
);

dfr_fn!(
    close_service_handle(h_sc_object: *mut core::ffi::c_void) -> i32,
    module = "advapi32.dll",
    api    = "CloseServiceHandle"
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
    let svc_s = String::from(parser.get_str());
    if svc_s.is_empty() {
        return Err("usage: sc-qtriggerinfo <servicename>");
    }

    let mut svc_buf = [0u8; 256];
    let slen = svc_s.len().min(255);
    svc_buf[..slen].copy_from_slice(&svc_s.as_bytes()[..slen]);

    let h_scm = unsafe {
        open_sc_manager_a(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT)
    }.map_err(|_| "open failed")?;

    if h_scm.is_null() {
        return Err("open failed");
    }

    let h_svc = unsafe {
        open_service_a(h_scm, svc_buf.as_ptr() as *const i8, SERVICE_QUERY_CONFIG)
    }.map_err(|_| "open failed")?;

    if h_svc.is_null() {
        unsafe { let _ = close_service_handle(h_scm); };
        return Err("open failed");
    }

    // Two-pass QueryServiceConfig2A for SERVICE_CONFIG_TRIGGER_INFO
    let mut bytes_needed: u32 = 0;
    let _ = unsafe {
        query_service_config2_a(
            h_svc,
            SERVICE_CONFIG_TRIGGER_INFO,
            core::ptr::null_mut(),
            0,
            &mut bytes_needed,
        )
    };

    let buf_size = if bytes_needed == 0 { 4096 } else { bytes_needed };
    let mut buf: Vec<u8> = alloc::vec![0u8; buf_size as usize];
    let ok = unsafe {
        query_service_config2_a(
            h_svc,
            SERVICE_CONFIG_TRIGGER_INFO,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut bytes_needed,
        )
    }.unwrap_or(0);

    unsafe {
        let _ = close_service_handle(h_svc);
        let _ = close_service_handle(h_scm);
    };

    if ok == 0 {
        return Err("query failed");
    }

    // SERVICE_TRIGGER_INFO layout (x64):
    // u32  cTriggers          @ offset 0
    // pad  4                  @ offset 4
    // *SERVICE_TRIGGER pTriggers @ offset 8
    // *void pReserved         @ offset 16
    //
    // SERVICE_TRIGGER layout (x64) = 32 bytes:
    // u32  dwTriggerType      @ offset 0
    // u32  dwAction           @ offset 4
    // GUID *pTriggerSubtype   @ offset 8
    // u32  cDataItems         @ offset 16
    // pad  4                  @ offset 20
    // *SERVICE_TRIGGER_SPECIFIC_DATA_ITEM pDataItems @ offset 24

    let c_triggers  = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const u32) };
    let trig_ptr    = unsafe { core::ptr::read_unaligned(buf.as_ptr().add(8) as *const *const u8) };

    println!("Service  : {}", svc_s.as_str());
    println!("Triggers : {}", c_triggers);

    if c_triggers > 0 && !trig_ptr.is_null() {
        // SERVICE_TRIGGER struct size on x64 = 32 bytes
        const TRIGGER_SIZE: usize = 32;
        for i in 0..c_triggers as usize {
            let tbase = unsafe { trig_ptr.add(i * TRIGGER_SIZE) };
            let ttype  = unsafe { core::ptr::read_unaligned(tbase as *const u32) };
            let action = unsafe { core::ptr::read_unaligned(tbase.add(4) as *const u32) };

            let type_str = trigger_type_str(ttype);
            let action_str = match action {
                1 => "SERVICE_TRIGGER_ACTION_SERVICE_START",
                2 => "SERVICE_TRIGGER_ACTION_SERVICE_STOP",
                _ => "UNKNOWN",
            };
            println!("  [{}] Type={} Action={}", i + 1, type_str, action_str);
        }
    }

    Ok(())
}

fn trigger_type_str(t: u32) -> &'static str {
    match t {
        SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL    => "DEVICE_INTERFACE_ARRIVAL",
        SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY     => "IP_ADDRESS_AVAILABILITY",
        SERVICE_TRIGGER_TYPE_DOMAIN_JOIN                 => "DOMAIN_JOIN",
        SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT         => "FIREWALL_PORT_EVENT",
        SERVICE_TRIGGER_TYPE_GROUP_POLICY                => "GROUP_POLICY",
        SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT            => "NETWORK_ENDPOINT",
        SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE  => "CUSTOM_SYSTEM_STATE_CHANGE",
        SERVICE_TRIGGER_TYPE_CUSTOM                      => "CUSTOM",
        _ => "UNKNOWN",
    }
}
