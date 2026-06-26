// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//! args — subcommand parser for xll-persist. Host-testable.

extern crate alloc;
use alloc::string::String;

#[derive(Debug, PartialEq, Eq)]
pub enum Cmd {
    Install(String),
    Remove(String),
    Status,
    Invalid(&'static str),
}

const MAX_PATH: usize = 260;

pub fn parse_pair(sub: &str, path: &str) -> Cmd {
    let s = sub.trim();
    let p = path.trim();
    let want_path = matches!(s, "install" | "remove");
    if want_path {
        if p.is_empty() { return Cmd::Invalid("path invalid"); }
        if p.len() >= MAX_PATH { return Cmd::Invalid("path invalid"); }
    }
    match s {
        "install" => Cmd::Install(String::from(p)),
        "remove"  => Cmd::Remove(String::from(p)),
        "status" | "" => Cmd::Status,
        _ => Cmd::Invalid("bad subcommand"),
    }
}

#[cfg(target_os = "windows")]
pub fn parse(parser: &mut rustbof::data::DataParser) -> Cmd {
    let sub = parser.get_str();
    let path = parser.get_str();
    parse_pair(sub, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::string::String;

    #[test]
    fn install_with_path() {
        assert_eq!(parse_pair("install", "\\\\srv\\s\\e.xll"),
                   Cmd::Install(String::from("\\\\srv\\s\\e.xll")));
    }

    #[test]
    fn remove_with_path() {
        assert_eq!(parse_pair("remove", "C:\\e.xll"),
                   Cmd::Remove(String::from("C:\\e.xll")));
    }

    #[test]
    fn status_no_path() {
        assert_eq!(parse_pair("status", ""), Cmd::Status);
    }

    #[test]
    fn empty_subcommand_defaults_to_status() {
        assert_eq!(parse_pair("", ""), Cmd::Status);
    }

    #[test]
    fn install_without_path_is_invalid() {
        assert_eq!(parse_pair("install", ""), Cmd::Invalid("path invalid"));
    }

    #[test]
    fn bad_subcommand_invalid() {
        assert_eq!(parse_pair("frobnicate", "x"), Cmd::Invalid("bad subcommand"));
    }

    #[test]
    fn path_at_or_over_max_invalid() {
        let long: String = core::iter::repeat('a').take(260).collect();
        assert_eq!(parse_pair("install", &long), Cmd::Invalid("path invalid"));
    }
}
