use pcap::Capture;
use pnet_packet::Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::sll::SLLPacket;
use pnet_packet::udp::UdpPacket;
use rtp_rs::RtpReader;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::path::Path;

pub struct PacketData {
    alice_file_path: String,
    bob_file_path: String,


    // keys are 64-bit hashes (truncated SHA-256) of the RTP payload
    seq_numbers_alice_outgoing: HashMap<u64, usize>,
    seq_numbers_alice_incoming: HashMap<u64, usize>,

    seq_numbers_bob_outgoing: HashMap<u64, usize>,
    seq_numbers_bob_incoming: HashMap<u64, usize>,
}

/// Combine an RTP timestamp and sequence number into a single u64.
///
/// Packs the 32-bit RTP timestamp into the high bits and the 16-bit RTP
/// sequence number into the low 16 bits of the returned value. This is
/// useful as an unsigned deterministic key preserving timestamp ordering.
pub fn ts_seq_to_u64(timestamp: u32, sequence: u16) -> u64 {
    ((timestamp as u64) << 16) | (sequence as u64)
}

impl PacketData {
    pub fn new<P: AsRef<Path>>(alice_path: P, bob_path: P) -> PacketData {
        PacketData {
            alice_file_path: alice_path.as_ref().to_string_lossy().to_string(),
            bob_file_path: bob_path.as_ref().to_string_lossy().to_string(),

            seq_numbers_alice_outgoing: HashMap::new(),
            seq_numbers_alice_incoming: HashMap::new(),
            seq_numbers_bob_outgoing: HashMap::new(),
            seq_numbers_bob_incoming: HashMap::new(),
        }
    }

    pub fn get_packet_drop_rate(&mut self) -> (f64, f64) {
        self.extract_packet_info();

        let mut packet_drop_alice = 0;
        let mut total_packets_alice = 0;
        for (key, count ) in self.seq_numbers_alice_outgoing.iter() {
            total_packets_alice += count;
            packet_drop_alice += count - self.seq_numbers_bob_incoming.get(key).unwrap_or(&0);
        }


        let mut packet_drop_bob = 0;
        let mut total_packets_bob = 0;
        for (key, count ) in self.seq_numbers_bob_outgoing.iter() {
            total_packets_bob += count;
            packet_drop_bob += count - self.seq_numbers_alice_incoming.get(key).unwrap_or(&0);
        }


        if total_packets_alice == 0 {
            total_packets_alice = 1;
        }

        if total_packets_bob == 0 {
            total_packets_bob = 1;
        }

        (
            packet_drop_alice as f64 / total_packets_alice as f64,
            packet_drop_bob as f64 / total_packets_bob as f64,
        )
    }


    fn extract_packet_info(&mut self) {
        let alice_path = self.alice_file_path.clone();
        Self::_extract_packet_info(
            &alice_path,
            &mut self.seq_numbers_alice_incoming,
            &mut self.seq_numbers_alice_outgoing,
        );

        let bob_path = self.bob_file_path.clone();
        Self::_extract_packet_info(
            &bob_path,
            &mut self.seq_numbers_bob_incoming,
            &mut self.seq_numbers_bob_outgoing,
        );
    }

    fn _extract_packet_info(path: &str, seq_numbers_incoming: &mut HashMap<u64, usize>, seq_numbers_outgoing: &mut HashMap<u64, usize>) {
        let mut cap = Capture::from_file(path)
            .map_err(|e| e.to_string())
            .unwrap();

        let mut fixed_ip: Ipv6Addr = Ipv6Addr::UNSPECIFIED;

        // Process each packet in the pcap file
        while let Ok(packet) = cap.next_packet() {
            // interpret packet as SLLPacket
            // TODO: Change incase it is an ethernet packet
            let sll_packet = SLLPacket::new(packet.data);
            if sll_packet.is_none() {
                continue;
            }

            let sll_packet = sll_packet.unwrap();
            let ipv6_packet = Ipv6Packet::new(sll_packet.payload());
            if ipv6_packet.is_none() {
                continue;
            }

            let ipv6_packet = ipv6_packet.unwrap();
            if fixed_ip.is_unspecified() {
                let src_ip = ipv6_packet.get_source();
                let dst_ip = ipv6_packet.get_destination();
                // whichever one has longer ipv6 name is the source, as the base station address is smaller
                if src_ip.to_string().len() > dst_ip.to_string().len() {
                    fixed_ip = src_ip;
                } else {
                    fixed_ip = dst_ip;
                }
            }

            let udp_packet = UdpPacket::new(ipv6_packet.payload());
            if udp_packet.is_none() {
                continue;
            }
            let udp_packet = udp_packet.unwrap();

            if udp_packet.payload().len() < 300 {
                continue;
            }

            let rtp_packet = RtpReader::new(udp_packet.payload());
            if !rtp_packet.is_ok() {
                println!("Non RTP Packet Found");
                continue;
            }

            let rtp_packet = rtp_packet.unwrap();
            let is_incoming = fixed_ip == ipv6_packet.get_destination();

            let val = ts_seq_to_u64(rtp_packet.timestamp().into(), rtp_packet.sequence_number().into());

            if is_incoming {
                // if already present, increment count and print length of payload
                if seq_numbers_incoming.contains_key(&val) {
                    println!("Duplicate key found. Payload length: {}", rtp_packet.payload().len());
                }

                *seq_numbers_incoming.entry(val).or_insert(0) += 1;
            } else {
                if seq_numbers_outgoing.contains_key(&val) {
                    println!("Duplicate key found. Payload length: {}", rtp_packet.payload().len());
                }

                *seq_numbers_outgoing.entry(val).or_insert(0) += 1;
            }
        }
    }

}
