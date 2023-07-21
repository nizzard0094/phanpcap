pub mod packet;

use bytes::Bytes;
use log::{error, info, trace, warn};
use packet::*;
use pnet::packet::{tcp, Packet};
use pnet::util::MacAddr;
use rand::prelude::*;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;
use tokio::time;

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 6;
const MPMC_BUFFER_LEN: usize = 512;
//const MPSC_BUFFER_LEN: usize = 128;
const MAX_UNACKED_LEN: u32 = 128 * 1024 * 1024; // 128MB

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct AddrTuple {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl AddrTuple {
    fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> AddrTuple {
        AddrTuple {
            local_addr,
            remote_addr,
        }
    }
}

struct Shared {
    tuples: RwLock<HashMap<AddrTuple, flume::Sender<Box<Bytes>>>>,
    //listening: RwLock<HashSet<u16>>,
    //interface_v4address: Ipv4Addr,
    pcap_sender: flume::Sender<Box<Bytes>>,
    //pcap_receiver: flume::Receiver<Box<Bytes>>,
    local_mac: MacAddr,
    remote_mac: MacAddr,
    //ready: mpsc::Sender<Socket>,
    tuples_purge: broadcast::Sender<AddrTuple>,
}

pub struct Stack {
    shared: Arc<Shared>,
    local_ip: Ipv4Addr,
    local_ip6: Option<Ipv6Addr>,
    //ready: mpsc::Receiver<Socket>,
}

pub enum State {
    Idle,
    SynSent,
    SynReceived,
    Established,
}

pub struct Socket {
    shared: Arc<Shared>,
    pcap_sender: flume::Sender<Box<Bytes>>,
    incoming: flume::Receiver<Box<Bytes>>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    local_mac: MacAddr,
    remote_mac: MacAddr,
    seq: AtomicU32,
    ack: AtomicU32,
    last_ack: AtomicU32,
    state: State,
}

/// A socket that represents a unique TCP connection between a server and client.
///
/// The `Socket` object itself satisfies `Sync` and `Send`, which means it can
/// be safely called within an async future.
///
/// To close a TCP connection that is no longer needed, simply drop this object
/// out of scope.
impl Socket {
    fn new(
        shared: Arc<Shared>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        ack: Option<u32>,
        state: State,
        pcap_sender: flume::Sender<Box<Bytes>>,
    ) -> (
        Socket,
        flume::Sender<Box<Bytes>>,
        //flume::Receiver<Box<Bytes>>,
    ) {
        let (incoming_tx, incoming_rx) = flume::bounded(MPMC_BUFFER_LEN);
        //let (outgoing_tx, outgoing_rx) = flume::bounded(MPMC_BUFFER_LEN);
        let local_mac = shared.local_mac;
        let remote_mac = shared.remote_mac;
        (
            Socket {
                shared,
                pcap_sender: pcap_sender,
                incoming: incoming_rx,
                local_addr,
                remote_addr,
                local_mac: local_mac,
                remote_mac: remote_mac,
                seq: AtomicU32::new(0),
                ack: AtomicU32::new(ack.unwrap_or(0)),
                last_ack: AtomicU32::new(ack.unwrap_or(0)),
                state,
            },
            incoming_tx,
            //outgoing_rx,
        )
    }

    fn build_tcp_packet(&self, flags: u16, payload: Option<&[u8]>) -> Bytes {
        let ack = self.ack.load(Ordering::Relaxed);
        self.last_ack.store(ack, Ordering::Relaxed);

        build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.local_mac,
            self.remote_mac,
            self.seq.load(Ordering::Relaxed),
            ack,
            flags,
            payload,
        )
    }

    /// Sends a datagram to the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the Tun socket returned an error
    /// and this socket must be closed.
    pub async fn send(&self, payload: &[u8]) -> Option<()> {
        match self.state {
            State::Established => {
                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, Some(payload));
                self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
                self.pcap_sender
                    .send_async(Box::new(buf))
                    .await
                    .ok()
                    .and(Some(()))
            }
            _ => unreachable!(),
        }
    }

    /// Attempt to receive a datagram from the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the TCP connection is broken
    /// and this socket must be closed.
    pub async fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        match self.state {
            State::Established => {
                self.incoming.recv_async().await.ok().and_then(|raw_buf| {
                    let (_v4_packet, tcp_packet) = parse_ip_packet(&raw_buf).unwrap();

                    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                        info!("Connection {} reset by peer", self);
                        return None;
                    }

                    let payload = tcp_packet.payload();

                    let new_ack = tcp_packet.get_sequence().wrapping_add(payload.len() as u32);
                    let last_ask = self.last_ack.load(Ordering::Relaxed);
                    self.ack.store(new_ack, Ordering::Relaxed);

                    if new_ack.overflowing_sub(last_ask).0 > MAX_UNACKED_LEN {
                        let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);

                        let pcap_sender = self.pcap_sender.clone();
                        let sock = format!("{} {}", self.local_addr, self.remote_addr);
                        tokio::spawn(async move {
                            if let Err(e) = pcap_sender.send_async(Box::new(buf)).await {
                                // This should not really happen as we have not sent anything for
                                // quite some time...
                                info!("Connection {} unable to send idling ACK back: {}", sock, e);
                            }
                        });
                    }

                    buf[..payload.len()].copy_from_slice(payload);

                    Some(payload.len())
                })
            }
            _ => unreachable!(),
        }
    }

    // async fn accept(mut self) {
    //     for _ in 0..RETRIES {
    //         match self.state {
    //             State::Idle => {
    //                 let buf = self.build_tcp_packet(tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None);
    //                 // ACK set by constructor
    //                 self.tun.send(&buf).await.unwrap();
    //                 self.state = State::SynReceived;
    //                 info!("Sent SYN + ACK to client");
    //             }
    //             State::SynReceived => {
    //                 let res = time::timeout(TIMEOUT, self.incoming.recv_async()).await;
    //                 if let Ok(buf) = res {
    //                     let buf = buf.unwrap();
    //                     let (_v4_packet, tcp_packet) = parse_ip_packet(&buf).unwrap();

    //                     if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
    //                         return;
    //                     }

    //                     if tcp_packet.get_flags() == tcp::TcpFlags::ACK
    //                         && tcp_packet.get_acknowledgement()
    //                             == self.seq.load(Ordering::Relaxed) + 1
    //                     {
    //                         // found our ACK
    //                         self.seq.fetch_add(1, Ordering::Relaxed);
    //                         self.state = State::Established;

    //                         info!("Connection from {:?} established", self.remote_addr);
    //                         let ready = self.shared.ready.clone();
    //                         if let Err(e) = ready.send(self).await {
    //                             error!("Unable to send accepted socket to ready queue: {}", e);
    //                         }
    //                         return;
    //                     }
    //                 } else {
    //                     info!("Waiting for client ACK timed out");
    //                     self.state = State::Idle;
    //                 }
    //             }
    //             _ => unreachable!(),
    //         }
    //     }
    // }

    async fn connect(&mut self) -> Option<()> {
        for _ in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN, None);
                    self.pcap_sender.send_async(Box::new(buf)).await.unwrap();
                    self.state = State::SynSent;
                    info!("Sent SYN to server");
                }
                State::SynSent => {
                    match time::timeout(TIMEOUT, self.incoming.recv_async()).await {
                        Ok(buf) => {
                            let buf = buf.unwrap();
                            let (_v4_packet, tcp_packet) = parse_ip_packet(&buf).unwrap();

                            if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                                return None;
                            }

                            if tcp_packet.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK
                                && tcp_packet.get_acknowledgement()
                                    == self.seq.load(Ordering::Relaxed) + 1
                            {
                                // found our SYN + ACK
                                self.seq.fetch_add(1, Ordering::Relaxed);
                                self.ack
                                    .store(tcp_packet.get_sequence() + 1, Ordering::Relaxed);

                                // send ACK to finish handshake
                                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                                self.pcap_sender.send_async(Box::new(buf)).await.unwrap();

                                self.state = State::Established;

                                info!("Connection to {:?} established", self.remote_addr);
                                return Some(());
                            }
                        }
                        Err(_) => {
                            info!("Waiting for SYN + ACK timed out");
                            self.state = State::Idle;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        None
    }
}

impl Drop for Socket {
    /// Drop the socket and close the TCP connection
    fn drop(&mut self) {
        let tuple = AddrTuple::new(self.local_addr, self.remote_addr);
        // dissociates ourself from the dispatch map
        assert!(self.shared.tuples.write().unwrap().remove(&tuple).is_some());
        // purge cache
        match self.shared.tuples_purge.send(tuple) {
            Ok(_) => {}
            Err(e) => {
                error!("{e}")
            }
        }

        let buf = build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.local_mac,
            self.remote_mac,
            self.seq.load(Ordering::Relaxed),
            0,
            tcp::TcpFlags::RST,
            None,
        );
        if let Err(e) = self.pcap_sender.try_send(Box::new(buf)) {
            warn!("Unable to send RST to remote end: {}", e);
        }

        info!("Fake TCP connection to {} closed", self);
    }
}

impl fmt::Display for Socket {
    /// User-friendly string representation of the socket
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(Fake TCP connection from {} to {})",
            self.local_addr, self.remote_addr
        )
    }
}

/// A userspace TCP state machine
impl Stack {
    /// Create a new stack, `tun` is an array of [`Tun`](tokio_tun::Tun).
    /// When more than one [`Tun`](tokio_tun::Tun) object is passed in, same amount
    /// of reader will be spawned later. This allows user to utilize the performance
    /// benefit of Multiqueue Tun support on machines with SMP.
    pub fn new(
        pcap_sender: flume::Sender<Box<Bytes>>,
        pcap_receiver: flume::Receiver<Box<Bytes>>,
        //interface_v4address: Ipv4Addr,
        local_ip: Ipv4Addr,
        local_ip6: Option<Ipv6Addr>,
        local_mac: MacAddr,
        remote_mac: MacAddr,
    ) -> Stack {
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            pcap_sender: pcap_sender,
            //pcap_receiver: pcap_receiver.clone(),
            //interface_v4address,
            //listening: RwLock::new(HashSet::new()),
            local_mac,
            remote_mac,
            tuples_purge: tuples_purge_tx.clone(),
        });

        for _ in 0..num_cpus::get() {
            tokio::spawn(Stack::reader_task(
                pcap_receiver.clone(),
                shared.clone(),
                tuples_purge_tx.subscribe(),
            ));
        }

        Stack {
            shared,
            local_ip,
            local_ip6, //ready: ready_rx,
        }
    }

    /// Listens for incoming connections on the given `port`.
    // pub fn listen(&mut self, port: u16) {
    //     assert!(self.shared.listening.write().unwrap().insert(port));
    // }

    /// Accepts an incoming connection.
    // pub async fn accept(&mut self) -> Socket {
    //     self.ready.recv().await.unwrap()
    // }

    /// Connects to the remote end. `None` returned means
    /// the connection attempt failed.
    pub async fn connect(&mut self, addr: SocketAddr) -> Option<Socket> {
        let mut rng = SmallRng::from_entropy();
        let local_port: u16 = rng.gen_range(1024..65535);
        let local_addr = SocketAddr::new(
            if addr.is_ipv4() {
                IpAddr::V4(self.local_ip)
            } else {
                IpAddr::V6(self.local_ip6.expect("IPv6 local address undefined"))
            },
            local_port,
        );
        let tuple = AddrTuple::new(local_addr, addr);
        let (mut sock, incoming) = Socket::new(
            self.shared.clone(),
            //self.shared.tun.choose(&mut rng).unwrap().clone(),
            local_addr,
            addr,
            None,
            State::Idle,
            self.shared.pcap_sender.clone(),
        );

        {
            let mut tuples = self.shared.tuples.write().unwrap();
            assert!(tuples.insert(tuple, incoming.clone()).is_none());
        }

        sock.connect().await.map(|_| sock)
    }

    async fn reader_task(
        pcap_receiver: flume::Receiver<Box<Bytes>>,
        shared: Arc<Shared>,
        mut tuples_purge: broadcast::Receiver<AddrTuple>,
    ) {
        let mut tuples: HashMap<AddrTuple, flume::Sender<Box<Bytes>>> = HashMap::new();

        loop {
            //let mut buf = BytesMut::zeroed(MAX_PACKET_LEN);

            tokio::select! {
                packet = pcap_receiver.recv_async() => {
                    let buf = packet.unwrap();

                    match parse_ip_packet(&buf) {
                        Some((ip_packet, tcp_packet)) => {
                            let local_addr =
                                SocketAddr::new(ip_packet.get_destination(), tcp_packet.get_destination());
                            let remote_addr = SocketAddr::new(ip_packet.get_source(), tcp_packet.get_source());

                            let tuple = AddrTuple::new(local_addr, remote_addr);
                            if let Some(c) = tuples.get(&tuple) {
                                if c.send_async(buf).await.is_err() {
                                    trace!("Cache hit, but receiver already closed, dropping packet");
                                }

                                continue;

                                // If not Ok, receiver has been closed and just fall through to the slow
                                // path below
                            } else {
                                trace!("Cache miss, checking the shared tuples table for connection");
                                let sender = {
                                    let tuples = shared.tuples.read().unwrap();
                                    tuples.get(&tuple).cloned()
                                };

                                if let Some(c) = sender {
                                    trace!("Storing connection information into local tuples");
                                    tuples.insert(tuple, c.clone());
                                    c.send_async(buf).await.unwrap();
                                    continue;
                                }
                            }
                        }
                        None => {
                            continue;
                        }
                    }
                },
                tuple = tuples_purge.recv() => {
                    let tuple = tuple.unwrap();
                    tuples.remove(&tuple);
                    trace!("Removed cached tuple: {:?}", tuple);
                }
            }
        }
    }
}
