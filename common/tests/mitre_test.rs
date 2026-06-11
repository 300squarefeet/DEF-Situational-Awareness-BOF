// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
use common::mitre::{Technique, format_banner};

#[test]
fn banner_format_snapshot() {
    let techs = &[
        Technique { id: "T1033", name: "System Owner/User Discovery", tactic: "Discovery" },
        Technique { id: "T1134", name: "Access Token Manipulation",   tactic: "Privilege Escalation" },
    ];
    let out = format_banner("whoami", techs);
    let expected = "\
================================================
  whoami — by Dani
================================================
  [MITRE] T1033 - System Owner/User Discovery (Discovery)
  [MITRE] T1134 - Access Token Manipulation (Privilege Escalation)
------------------------------------------------
";
    assert_eq!(out, expected);
}

#[test]
fn banner_empty_techniques() {
    let out = format_banner("stub", &[]);
    assert!(out.contains("stub — by Dani"));
    assert!(out.contains("------------------------------------------------"));
}
