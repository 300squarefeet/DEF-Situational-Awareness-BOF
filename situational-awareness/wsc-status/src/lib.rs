#![no_std]
#![cfg_attr(not(test), no_main)]
use common::{dfr_fn, mitre::Technique};
use rustbof::{eprintln, println};
const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1518.001",
    name: "Security Software Discovery",
    tactic: "Discovery",
}];
dfr_fn!(wsc_get_security_provider_health(providers:u32,health:*mut u32)->i32,module="wscapi.dll",api="WscGetSecurityProviderHealth");
#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    for (name, mask) in [
        ("Firewall", 1u32),
        ("Auto Update", 2),
        ("Antivirus", 4),
        ("Antispyware", 8),
        ("Internet Settings", 16),
        ("UAC", 32),
        ("Service", 64),
    ] {
        let mut h = 0u32;
        match unsafe { wsc_get_security_provider_health(mask, &mut h) } {
            Ok(hr) if hr >= 0 => println!(
                "{:<18} {}",
                name,
                match h {
                    0 => "Good",
                    1 => "Not monitored",
                    2 => "Poor",
                    3 => "Snoozed",
                    _ => "Unknown",
                }
            ),
            _ => eprintln!("{:<18} unavailable", name),
        }
    }
}
