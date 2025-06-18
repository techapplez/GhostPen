use pnet::datalink::{self, Channel::Ethernet, MacAddr};
use std::fs;
use std::process::Command;
use std::str::FromStr;

pub(crate) fn find_mac(interface: &str, ip: &str, label: &str) -> Option<MacAddr> {
    let output = Command::new("arp-scan")
        .arg("-I")
        .arg(interface)
        .arg(ip)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.starts_with(ip) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 {
                println!("{} MAC: {}", label, fields[1]);
                return MacAddr::from_str(fields[1]).ok();
            }
        }
    }
    let arp_table = fs::read_to_string("/proc/net/arp").ok()?;
    for line in arp_table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.get(0) == Some(&ip) && fields.len() >= 4 {
            println!("{} MAC (from ARP cache): {}", label, fields[3]);
            return MacAddr::from_str(fields[3]).ok();
        }
    }
    None
}
