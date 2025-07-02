use pnet::datalink::MacAddr;

#[cfg(target_os = "linux")]
pub(crate) fn find_mac(interface: &str, ip: &str, label: &str) -> Option<MacAddr> {
    use std::fs;
    use std::str::FromStr;

    let arp_table = fs::read_to_string("/proc/net/arp").ok()?;
    for line in arp_table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 6 && fields[0] == ip && fields[5] == interface {
            let mac_str = fields[3];
            println!("{} MAC (from ARP cache): {}", label, mac_str);
            return MacAddr::from_str(mac_str).ok();
        }
    }
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
