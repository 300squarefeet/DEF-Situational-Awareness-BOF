// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
use common::hash::{djb2, djb2_case_insensitive};

#[test]
fn djb2_known_vectors() {
    // Pre-computed via reference impl; if these change, downstream DFR
    // matching breaks everywhere.
    assert_eq!(djb2(b""),          5381);
    assert_eq!(djb2(b"a"),         177670);
    assert_eq!(djb2(b"ntdll.dll"), 0x22d3b5ed);
}

#[test]
fn djb2_case_insensitive_matches_upper_lower() {
    assert_eq!(djb2_case_insensitive(b"NTDLL.DLL"),
               djb2_case_insensitive(b"ntdll.dll"));
    assert_eq!(djb2_case_insensitive(b"NtOpenProcessToken"),
               djb2_case_insensitive(b"ntopenprocesstoken"));
}

#[test]
fn djb2_no_collisions_in_ntdll_export_sample() {
    let exports: &[&[u8]] = &[
        b"NtOpenProcessToken", b"NtQueryInformationToken", b"NtAdjustPrivilegesToken",
        b"NtProtectVirtualMemory", b"NtAllocateVirtualMemory", b"NtWriteVirtualMemory",
        b"NtReadVirtualMemory", b"NtCreateThreadEx", b"NtQueueApcThread",
        b"NtSuspendProcess", b"NtResumeProcess", b"NtDeviceIoControlFile",
        b"NtQuerySystemInformation", b"NtQueryInformationProcess",
    ];
    let mut hashes: Vec<u32> = exports.iter().map(|s| djb2(s)).collect();
    hashes.sort();
    for w in hashes.windows(2) { assert_ne!(w[0], w[1], "collision found"); }
}
