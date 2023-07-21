pub mod fake_tcp;
pub mod pcap_channel;
pub mod utils;

use clap::{crate_version, Arg, ArgAction, Command};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::{Socket, Stack};
use libarp::client::ArpClient;

use log::{debug, error, info};
use pnet::datalink;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, RwLock};
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::utils::{async_get_ip_and_router_ip_dhcp, generate_random_unicast_mac_address, new_udp};
pub const UDP_TTL: Duration = Duration::from_secs(180);

#[tokio::main]
async fn main() -> io::Result<()> {
    //std::env::set_var("RUST_LOG", "trace");
    pretty_env_logger::init();

    let matches = Command::new("phanpcap Client")
        .version(crate_version!())
        .author("wesam adel")
        .arg(Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("IP:PORT")
                .help("Sets the IP and port where Phantun Client listens for incoming UDP datagrams")
        )
        .arg(Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Client connects to Phantun Server")
        )
                .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .required(false)
                .value_name("\\Device\\NPF_{GUID}")
                .help("Sets network interface that will be used. default get interface of default route")
        )
        .arg(
            Arg::new("source")
                .short('s')
                .long("source")
                .required(false)
                .value_name("IP")
                .help("Sets the address of out going traffic. default get from dhcp")
                .requires("gateway")
        )
        .arg(Arg::new("gateway")
                .short('g')
                .long("gateway")
                .required(false)
                .value_name("IP")
                .help("Sets the address of internet gateway. default get from dhcp")
                .requires("source")
        )
        .arg(Arg::new("mac")
                .short('m')
                .long("macaddr")
                .required(false)
                .value_name("MAC")
                .help("Sets the mac address of out going traffic. default random")

        )
        .arg(Arg::new("interfaces")
                .long("interfaces")
                .required(false)
                .help("list interfaces")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(&["local", "remote","interface","source","gateway"]),
        )
        .get_matches();

    let interfaces = datalink::interfaces();
    if matches.get_flag("interfaces") {
        for i in &interfaces {
            println!("{}", i.description);
            println!("name: {} \nmac: {}", i.name, i.mac.unwrap_or_default());
            for ip in &i.ips {
                if let pnet::ipnetwork::IpNetwork::V4(e) = ip {
                    println!("{}", e.ip());
                }
            }
            println!("");
        }
        return Ok(());
    }

    let local_addr: SocketAddr = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local address");
    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .find(|ip| ip.is_ipv4())
        .expect("unable to resolve remote host name");
    info!("Remote address is: {}", remote_addr);

    let interface = match matches.get_one::<String>("interface") {
        Some(name) => interfaces
            .iter()
            .find(|i| i.name == *name)
            .expect(&format!("no interface named {}", name)),
        None => {
            let manager = net_route::Handle::new()?;
            let default_route = manager.default_route().await?.unwrap();
            interfaces
                .iter()
                .find(|e| e.index == default_route.ifindex.unwrap())
                .expect("interface of default route not found")
        }
    };

    println!("{}", interface.name);

    let source_mac_address: MacAddr = match matches.get_one::<String>("mac") {
        Some(m) => m.parse().unwrap(),
        None => generate_random_unicast_mac_address(),
    };
    debug!("source_mac_address {}", source_mac_address);

    let (loacl_ip, gateway_ip) = match (
        matches.get_one::<String>("source"),
        matches.get_one::<String>("gateway"),
    ) {
        (None, None) => {
            let (loacl_ip, gateway_ip) =
                async_get_ip_and_router_ip_dhcp(&interface.name, source_mac_address).await;
            debug!("dhcp leased ip {} gateway ip {}", loacl_ip, gateway_ip);
            (loacl_ip, gateway_ip)
        }
        (Some(loacl_ip), Some(gateway_ip)) => {
            (loacl_ip.parse().unwrap(), gateway_ip.parse().unwrap())
        }
        _ => unreachable!(),
    };

    let mut client = ArpClient::new_with_iface_name(interface.name.as_str()).unwrap();
    let gateway_mac: MacAddr = client.ip_to_mac(gateway_ip, None).await.unwrap().into();
    debug!("gateway mac: {}", gateway_mac);
    let pcap_filter = &format!(
        "src host {} and tcp port {}",
        remote_addr.ip().to_string(),
        remote_addr.port().to_string()
    );

    let (pcap_sender, pcap_receiver) = pcap_channel::new(&interface.name, pcap_filter);

    utils::create_arp_client(&interface.name, loacl_ip, source_mac_address);

    let num_cpus = num_cpus::get();

    let mut stack = Stack::new(
        pcap_sender.clone(),
        pcap_receiver,
        loacl_ip,
        None,
        source_mac_address,
        gateway_mac,
    );

    let connections = Arc::new(RwLock::new(HashMap::<SocketAddr, Arc<Socket>>::new()));

    let main_loop = tokio::spawn(async move {
        let mut buf_r = [0u8; MAX_PACKET_LEN];
        let udp_sock = Arc::new(new_udp(local_addr));
        loop {
            let (size, addr) = match udp_sock.recv_from(&mut buf_r).await {
                Ok((size, addr)) => (size, addr),
                Err(e) => match e.kind() {
                    std::io::ErrorKind::ConnectionReset => {
                        error!("udpSocket Error {e}");
                        continue;
                    }

                    _ => {
                        error!("udpSocket Error {e}");
                        return Err(e);
                    }
                },
            };

            if let Some(sock) = connections.read().await.get(&addr) {
                let buf = buf_r[..size].to_owned();
                let sock = sock.clone();
                tokio::spawn(async move {
                    let buf = buf;
                    sock.send(&buf).await;
                });

                continue;
            }

            info!("New UDP client from {}", addr);
            let sock = stack.connect(remote_addr).await;
            if sock.is_none() {
                error!("Unable to connect to remote {}", remote_addr);
                continue;
            }

            let sock = Arc::new(sock.unwrap());

            // send first packet
            if sock.send(&buf_r[..size]).await.is_none() {
                continue;
            }

            assert!(connections
                .write()
                .await
                .insert(addr, sock.clone())
                .is_none());
            debug!("inserted fake TCP socket into connection table");

            let packet_received = Arc::new(Notify::new());
            let quit = CancellationToken::new();

            for i in 0..num_cpus {
                let sock = sock.clone();
                let quit = quit.clone();
                let packet_received = packet_received.clone();
                let udp_sock = new_udp(local_addr);
                udp_sock.connect(addr).await.unwrap();
                tokio::spawn(async move {
                    //let mut buf_udp = [0u8; MAX_PACKET_LEN];
                    let mut buf_tcp = [0u8; MAX_PACKET_LEN];

                    loop {
                        tokio::select! {
                            // Ok(size) = udp_sock.recv(&mut buf_udp) => {
                            //     if sock.send(&buf_udp[..size]).await.is_none() {
                            //         debug!("removed fake TCP socket from connections table");
                            //         quit.cancel();
                            //         return;
                            //     }

                            //     packet_received.notify_one();
                            // },
                            res = sock.recv(&mut buf_tcp) => {
                                match res {
                                    Some(size) => {
                                        if size > 0 {
                                            if let Err(e) = udp_sock.send(&buf_tcp[..size],).await {
                                                error!("Unable to send UDP packet to {}: {}, closing connection", e, addr);
                                                quit.cancel();
                                                return;
                                            }
                                        }
                                    },
                                    None => {
                                        debug!("removed fake TCP socket from connections table");
                                        quit.cancel();
                                        return;
                                    },
                                }

                                packet_received.notify_one();
                            },
                            _ = quit.cancelled() => {
                                debug!("worker {} terminated", i);
                                return;
                            },
                        };
                    }
                });
            }

            let connections = connections.clone();
            tokio::spawn(async move {
                loop {
                    let read_timeout = time::sleep(UDP_TTL);
                    let packet_received_fut = packet_received.notified();

                    tokio::select! {
                        _ = read_timeout => {
                            info!("No traffic seen in the last {:?}, closing connection", UDP_TTL);
                            connections.write().await.remove(&addr);
                            debug!("removed fake TCP socket from connections table");

                            quit.cancel();
                            return;
                        },
                        _ = quit.cancelled() => {
                            connections.write().await.remove(&addr);
                            debug!("removed fake TCP socket from connections table");
                            return;
                        },
                        _ = packet_received_fut => {},
                    }
                }
            });
        }
    });

    tokio::join!(main_loop).0.unwrap()
}
