use pnet::datalink::MacAddr;
use regex::Regex;

#[cfg(target_os = "linux")]
use std::process::Command;
use std::str::FromStr;

pub(crate) fn find_mac(_interface: &str, ip: &str, label: &str) -> Option<MacAddr> {
    let output = Command::new("arping").arg("-f").arg(ip).output().ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mac_regex = Regex::new(r"\[([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\]").ok()?;

    for line in stdout.lines() {
        if line.contains("Unicast reply from") {
            if let Some(caps) = mac_regex.captures(line) {
                if let Some(mac) = caps.get(1) {
                    let mac_str = mac.as_str();
                    println!("{} MAC (from arping): {}", label, mac_str);
                    let mac_str = MacAddr::from_str(mac_str).ok();
                    return mac_str;
                }
            }
        }
    }

    eprintln!("❌ No MAC found for {} via arping", ip);
    None
}

#[cfg(target_os = "windows")]
pub(crate) fn find_mac(_interface: &str, ip: &str, label: &str) -> Option<MacAddr> {
    use std::process::Command;
    use std::str::FromStr;

    let output = Command::new("arp").arg("-a").output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let trimmed = line.trim_start();
        if !trimmed
            .chars()
            .next()
            .map(|c| c.is_digit(10))
            .unwrap_or(false)
        {
            continue;
        }
        if trimmed.starts_with(ip) {
            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            if fields.len() >= 2 {
                let mac_str = fields[1].replace("-", ":");
                println!("{} MAC: {}", label, mac_str);
                return MacAddr::from_str(&mac_str).ok();
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
pub(crate) fn find_mac(_interface: &str, ip: &str, label: &str) -> Option<MacAddr> {
    use std::process::Command;
    use std::str::FromStr;

    let output = Command::new("arp").arg("-a").output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        if line.contains(ip) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(at_pos) = parts.iter().position(|&s| s == "at") {
                if let Some(mac_str) = parts.get(at_pos + 1) {
                    println!("{} MAC: {}", label, mac_str);
                    return MacAddr::from_str(mac_str).ok();
                }
            }
        }
    }
    None
}
