use bytes::{Bytes, BytesMut};
use dhcproto::{v4, Decodable, Decoder, Encodable, Encoder};
use internet_checksum::Checksum;
use pcap::Capture;
use pnet::{
    packet::{
        arp::MutableArpPacket,
        ethernet::{EtherTypes, MutableEthernetPacket},
        ip, ipv4, udp, Packet,
    },
    util::MacAddr,
};
use rand::Rng;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
const MAC_ADDRESS_SIZE: u8 = 6;
const IPV4_SIZE: u8 = 4;
const UDP_HEADER_LEN: usize = 8;

pub fn new_udp(local_addr: SocketAddr) -> UdpSocket {
    let udp_sock = socket2::Socket::new(
        if local_addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    udp_sock.set_reuse_address(true).unwrap();
    udp_sock.set_nonblocking(true).unwrap();
    udp_sock.bind(&socket2::SockAddr::from(local_addr)).unwrap();
    let udp_sock: std::net::UdpSocket = udp_sock.into();
    udp_sock.try_into().unwrap()
}
pub fn generate_random_unicast_mac_address() -> MacAddr {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 6];
    rng.fill(&mut bytes[..]);
    bytes[0] = (bytes[0] & 0xfe) | 0x02;
    MacAddr::from(bytes)
}

pub fn create_arp_client(device_name: &str, ip_address: Ipv4Addr, mac_address: MacAddr) {
    let mut pcap = Capture::from_device(device_name)
        .unwrap()
        .immediate_mode(true)
        .promisc(true)
        .timeout(1000)
        .open()
        .unwrap();

    let pcap_filter = &format!("arp dst host {} and arp[6:2] = 1", ip_address);
    pcap.filter(pcap_filter, true).unwrap();

    std::thread::spawn(move || {
        let mut buff = [0u8; 42];
        {
            let (ether_buf, arp_buff) = buff.split_at_mut(ETHERNET_HEADER_LEN);
            let mut mut_ether_packet = MutableEthernetPacket::new(ether_buf).unwrap();
            mut_ether_packet.set_source(mac_address);
            mut_ether_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Arp);
            let mut mut_arp_packet = MutableArpPacket::new(arp_buff).unwrap();
            mut_arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
            mut_arp_packet.set_protocol_type(pnet::packet::ethernet::EtherTypes::Ipv4);
            mut_arp_packet.set_hw_addr_len(MAC_ADDRESS_SIZE);
            mut_arp_packet.set_proto_addr_len(IPV4_SIZE);
            mut_arp_packet.set_operation(pnet::packet::arp::ArpOperations::Reply);
            mut_arp_packet.set_sender_hw_addr(mac_address);
            mut_arp_packet.set_sender_proto_addr(ip_address);
        }

        loop {
            if let Ok(pcapframe) = pcap.next_packet() {
                let wire_packet = pcapframe.data;
                buff[0..6].copy_from_slice(&wire_packet[6..12]);
                buff[32..42].copy_from_slice(&wire_packet[22..32]);

                pcap.sendpacket(buff).unwrap();
            }
        }
    });
}

pub fn get_ip_and_router_ip_dhcp(device_name: &str, mac_addr: MacAddr) -> (Ipv4Addr, Ipv4Addr) {
    let udp_server_port = 67;
    let udp_client_port = 68;
    let dhcp_offset = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN;
    let local_addr = format!("0.0.0.0:{udp_client_port}").parse().unwrap();
    let remote_addr = format!("255.255.255.255:{udp_server_port}")
        .parse()
        .unwrap();
    let remote_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();
    let xid: u32 = rand::thread_rng().gen();
    let mut pcap = Capture::from_device(device_name)
        .unwrap()
        .immediate_mode(true)
        .promisc(true)
        .timeout(10000)
        .open()
        .unwrap();

    let pcap_filter = &format!(
        "udp[36:4] = 0x{} and udp[40:2] = 0x{} and udp[8] = 2 and udp dst port {}",
        bytes_to_hex(&mac_addr.octets()[..4]),
        bytes_to_hex(&mac_addr.octets()[4..]),
        udp_client_port
    );
    pcap.filter(pcap_filter, true).unwrap();

    let chaddr = Vec::from(mac_addr.octets());
    let zero_addr = "0.0.0.0".parse().unwrap();
    let mut msg =
        v4::Message::new_with_id(xid, zero_addr, zero_addr, zero_addr, zero_addr, &chaddr);
    msg.set_flags(v4::Flags::default().set_broadcast()) // set broadcast to true
        .opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));
    msg.opts_mut()
        .insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::DomainName,
        ]));
    msg.opts_mut()
        .insert(v4::DhcpOption::ClientIdentifier(chaddr));

    let discover_packet = {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e).unwrap();
        build_udp_packet(local_addr, remote_addr, mac_addr, remote_mac, &buf)
    };
    pcap.sendpacket(discover_packet).unwrap();

    let mut offer = None;
    for _ in 0..10 {
        if let Ok(pcapframe) = pcap.next_packet() {
            let wire_dhcp_packet = pcapframe.data[dhcp_offset..].as_ref();
            let res_msg = v4::Message::decode(&mut Decoder::new(&wire_dhcp_packet)).unwrap();
            if res_msg.xid() == xid {
                offer = Some(res_msg);
                break;
            }
        }
    }
    let offer = offer.unwrap();
    let offerd_ip = offer.yiaddr();
    let router_ip =
        if let v4::DhcpOption::Router(ip) = offer.opts().get(v4::OptionCode::Router).unwrap() {
            Some(ip)
        } else {
            None
        }
        .unwrap()
        .clone();
    let mut request = msg;
    request
        .opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Request));
    request
        .opts_mut()
        .insert(v4::DhcpOption::RequestedIpAddress(offerd_ip));
    let request_packet = {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        request.encode(&mut e).unwrap();
        build_udp_packet(local_addr, remote_addr, mac_addr, remote_mac, &buf)
    };
    pcap.sendpacket(request_packet).unwrap();

    for _ in 0..10 {
        if let Ok(pcapframe) = pcap.next_packet() {
            let wire_dhcp_packet = pcapframe.data[dhcp_offset..].as_ref();
            let res_msg = v4::Message::decode(&mut Decoder::new(&wire_dhcp_packet)).unwrap();
            if res_msg.xid() == xid {
                if let v4::DhcpOption::MessageType(msgtyp) =
                    res_msg.opts().get(v4::OptionCode::MessageType).unwrap()
                {
                    match msgtyp {
                        &v4::MessageType::Ack => {
                            break;
                        }
                        &v4::MessageType::Nak => {
                            panic!("dhcp send Nak")
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    (offerd_ip, router_ip.first().unwrap().to_owned())
}

pub async fn async_get_ip_and_router_ip_dhcp(
    device_name: &str,
    mac_addr: MacAddr,
) -> (Ipv4Addr, Ipv4Addr) {
    let device_name = device_name.to_owned();
    tokio::task::spawn_blocking(move || get_ip_and_router_ip_dhcp(&device_name, mac_addr))
        .await
        .unwrap()
}

fn build_udp_packet(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    local_mac: MacAddr,
    remote_mac: MacAddr,
    payload: &[u8],
) -> Bytes {
    let total_udp_len = UDP_HEADER_LEN + payload.len();
    let total_ip_len = IPV4_HEADER_LEN + total_udp_len;
    let mut buf = BytesMut::zeroed(ETHERNET_HEADER_LEN + total_ip_len);
    let mut ether_buf = buf.split_to(ETHERNET_HEADER_LEN);
    let mut ip_buf = buf.split_to(IPV4_HEADER_LEN);
    let mut udp_buf = buf.split_to(total_udp_len);
    assert_eq!(0, buf.len());

    let mut ether = MutableEthernetPacket::new(&mut ether_buf).unwrap();
    ether.set_ethertype(EtherTypes::Ipv4);
    ether.set_source(local_mac);
    ether.set_destination(remote_mac);
    match (local_addr, remote_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
            let mut v4 = ipv4::MutableIpv4Packet::new(&mut ip_buf).unwrap();
            v4.set_version(4);
            v4.set_header_length(IPV4_HEADER_LEN as u8 / 4);
            v4.set_next_level_protocol(ip::IpNextHeaderProtocols::Udp);
            v4.set_ttl(64);
            v4.set_source(*local.ip());
            v4.set_destination(*remote.ip());
            v4.set_total_length(total_ip_len.try_into().unwrap());
            v4.set_flags(ipv4::Ipv4Flags::DontFragment);
            let mut cksm = Checksum::new();
            cksm.add_bytes(v4.packet());
            v4.set_checksum(u16::from_be_bytes(cksm.checksum()));
        }
        _ => {}
    };

    let mut udp = udp::MutableUdpPacket::new(&mut udp_buf).unwrap();
    udp.set_source(local_addr.port());
    udp.set_destination(remote_addr.port());
    udp.set_length(total_udp_len as u16);
    udp.set_payload(payload);

    let mut cksm = Checksum::new();
    let ip::IpNextHeaderProtocol(udp_protocol) = ip::IpNextHeaderProtocols::Udp;
    match (local_addr, remote_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
            cksm.add_bytes(&local.ip().octets());
            cksm.add_bytes(&remote.ip().octets());

            let mut pseudo = [0u8, udp_protocol, 0, 0];
            pseudo[2..].copy_from_slice(&(total_udp_len as u16).to_be_bytes());
            cksm.add_bytes(&pseudo);
        }
        _ => {}
    };

    cksm.add_bytes(udp.packet());
    udp.set_checksum(u16::from_be_bytes(cksm.checksum()));
    ip_buf.unsplit(udp_buf);
    ether_buf.unsplit(ip_buf);
    ether_buf.freeze()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join("")
}
