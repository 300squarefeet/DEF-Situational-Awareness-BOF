// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! MITRE ATT&CK runtime banner. Printed by every BOF before its main logic
//! so operators see exactly which technique they're firing.

use alloc::string::String;
use core::fmt::Write;

pub struct Technique {
    pub id: &'static str,      // e.g. "T1057"
    pub name: &'static str,    // e.g. "Process Discovery"
    pub tactic: &'static str,  // e.g. "Discovery"
}

const RULE_TOP: &str = "================================================";
const RULE_BOT: &str = "------------------------------------------------";

/// Build the banner string (pure — for testability).
pub fn format_banner(crate_name: &str, techniques: &[Technique]) -> String {
    let mut s = String::with_capacity(256);
    let _ = writeln!(s, "{}", RULE_TOP);
    let _ = writeln!(s, "  {}", crate_name);
    let _ = writeln!(s, "{}", RULE_TOP);
    for t in techniques {
        let _ = writeln!(s, "  [MITRE] {} - {} ({})", t.id, t.name, t.tactic);
    }
    let _ = writeln!(s, "{}", RULE_BOT);
    s
}

/// Print the banner via rustbof's `print!` macro (auto-buffered to Beacon output).
pub fn print_banner(crate_name: &str, techniques: &[Technique]) {
    let b = format_banner(crate_name, techniques);
    rustbof::print!("{}", b);
}
