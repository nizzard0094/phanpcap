use bytes::Bytes;
use log::error;
use pcap::Capture;

pub fn new(
    device_name: &str,
    pcap_filter: &str,
) -> (flume::Sender<Box<Bytes>>, flume::Receiver<Box<Bytes>>) {
    let (tx, pcap_receiver) = flume::bounded::<Box<Bytes>>(10);

    let mut rx_cap = Capture::from_device(device_name)
        .unwrap()
        .immediate_mode(true)
        .promisc(true)
        .timeout(1000)
        .open()
        .unwrap();

    rx_cap.filter(pcap_filter, true).unwrap();
    std::thread::spawn(move || loop {
        match rx_cap.next_packet() {
            Ok(packet) => {
                if let Err(_) = tx.send(Box::new(Bytes::copy_from_slice(&packet.data))) {
                    return;
                }
            }
            Err(_e) => {
                //trace!("receive_cap{}", e);
            }
        }
    });
    let (pcap_sender, rx) = flume::bounded::<Box<Bytes>>(10);
    let mut tx_cap = Capture::from_device(device_name)
        .unwrap()
        .immediate_mode(true)
        .promisc(true)
        .snaplen(1)
        .buffer_size(2)
        .open()
        .unwrap();

    std::thread::spawn(move || {
        let mut sq = pcap::sendqueue::SendQueue::new(1024 * 1024).unwrap();
        loop {
            let mut packets = rx.drain();
            match packets.len() {
                0 => match rx.recv() {
                    Ok(packet) => {
                        tx_cap.sendpacket(*packet).unwrap();
                    }
                    Err(e) => {
                        error!("send_cap error => {e}");
                        return;
                    }
                },
                1 => {
                    tx_cap.sendpacket(*packets.next().unwrap()).unwrap();
                }
                _ => {
                    for p in packets {
                        sq.queue(None, &*p).unwrap();
                    }
                    sq.transmit(&mut tx_cap, pcap::sendqueue::SendSync::Off)
                        .unwrap();
                }
            }
            // match rx.recv() {
            //     Ok(packet) => {
            //         if rx.len() > 2 {
            //             sq.queue(None, &*packet).unwrap();
            //             let packets = rx.drain();
            //             for p in packets {
            //                 sq.queue(None, &*p).unwrap();
            //             }
            //             sq.transmit(&mut tx_cap, pcap::sendqueue::SendSync::Off)
            //                 .unwrap();
            //         } else {
            //             tx_cap.sendpacket(*packet).unwrap();
            //         }
            //     }
            //     Err(e) => {
            //         error!("send_cap error => {e}");
            //         return;
            //     }
            // }
        }
    });

    (pcap_sender, pcap_receiver)
}
