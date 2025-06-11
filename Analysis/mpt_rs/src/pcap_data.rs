use chrono::NaiveDateTime;
use ndarray::Array1;
use ndarray_stats::{QuantileExt, SummaryStatisticsExt};
use pcap::Capture;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::sll::SLLPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;
use regex::Regex;
use statrs::statistics::{Data, OrderStatistics};
use std::net::Ipv6Addr;
use std::path::Path;
use std::result::Result;

type PacketInfo = (f64, f64, bool);

pub struct PacketData {
    pcap_file_path: String,
    bin_width: u8,
    fixed_ip: Ipv6Addr,
    datetime: NaiveDateTime,

    // packet statistics
    total_packets: f64,
    total_packets_in: f64,
    total_packets_out: f64,

    // Byte statistics
    total_bytes: f64,
    total_bytes_in: f64,
    total_bytes_out: f64,

    // Size statistics
    packet_size: Vec<f64>,
    packet_size_in: Vec<f64>,
    packet_size_out: Vec<f64>,

    // Bin statistics
    out_packet_bins: Vec<usize>,
    in_packet_bins: Vec<usize>,

    // Time statistics
    packet_time: Vec<f64>,
    packet_time_in: Vec<f64>,
    packet_time_out: Vec<f64>,
    packet_times_abs: Vec<f64>,

    // Outgoing burst statistics
    out_bursts_packets: Vec<f64>,
    out_bursts_bytes: Vec<f64>,
    out_bursts_time: Vec<f64>,
    out_current_burst: f64,
    out_current_burst_start: f64,
    out_current_burst_size: f64,

    // Incoming burst statistics
    in_bursts_packets: Vec<f64>,
    in_bursts_bytes: Vec<f64>,
    in_bursts_time: Vec<f64>,
    in_current_burst: f64,
    in_current_burst_start: f64,
    in_current_burst_size: f64,
}

impl PacketData {
    pub fn new<P: AsRef<Path>>(file_path: P) -> PacketData {
        let out_pkt_bins: Vec<usize> = vec![0; 300];
        let in_pkt_bins: Vec<usize> = vec![0; 300];

        // finding the datetime from the filename
        let pattern = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)";
        let fmt = "%Y-%m-%dT%H:%M:%S%.6f";

        let re = Regex::new(pattern).map_err(|e| e.to_string()).unwrap();
        let file_name = file_path.as_ref().file_name().unwrap().to_str().unwrap();
        let datetime_str = re.captures(file_name).unwrap().get(0).unwrap().as_str();
        let datetime = NaiveDateTime::parse_from_str(datetime_str, fmt).unwrap();

        PacketData {
            pcap_file_path: file_path.as_ref().to_string_lossy().to_string(),
            bin_width: 5,
            fixed_ip: Ipv6Addr::UNSPECIFIED,
            datetime,

            // packet statistics
            total_packets: 0.0,
            total_packets_in: 0.0,
            total_packets_out: 0.0,

            // Byte statistics
            total_bytes: 0.0,
            total_bytes_in: 0.0,
            total_bytes_out: 0.0,

            // Size statistics
            packet_size: Vec::new(),
            packet_size_in: Vec::new(),
            packet_size_out: Vec::new(),

            // Bin statistics
            out_packet_bins: out_pkt_bins,
            in_packet_bins: in_pkt_bins,

            // Time statistics
            packet_time: Vec::new(),
            packet_time_in: Vec::new(),
            packet_time_out: Vec::new(),
            packet_times_abs: Vec::new(),

            // Outgoing burst statistics
            out_bursts_packets: Vec::new(),
            out_bursts_bytes: Vec::new(),
            out_bursts_time: Vec::new(),
            out_current_burst: 0.0,
            out_current_burst_start: 0.0,
            out_current_burst_size: 0.0,

            // Incoming burst statistics
            in_bursts_packets: Vec::new(),
            in_bursts_bytes: Vec::new(),
            in_bursts_time: Vec::new(),
            in_current_burst: 0.0,
            in_current_burst_start: 0.0,
            in_current_burst_size: 0.0,
        }
    }

    fn reset(&mut self) {
        self.total_packets = 0.0;
        self.total_packets_in = 0.0;
        self.total_packets_out = 0.0;

        // Byte statistics
        self.total_bytes = 0.0;
        self.total_bytes_in = 0.0;
        self.total_bytes_out = 0.0;

        // Size statistics
        self.packet_size.clear();
        self.packet_size_in.clear();
        self.packet_size_out.clear();

        // Bin statistics
        self.out_packet_bins = vec![0; 300];
        self.in_packet_bins = vec![0; 300];

        // Time statistics
        self.packet_time.clear();
        self.packet_time_in.clear();
        self.packet_time_out.clear();
        self.packet_times_abs.clear();

        // Outgoing burst statistics
        self.out_bursts_packets.clear();
        self.out_bursts_bytes.clear();
        self.out_bursts_time.clear();
        self.out_current_burst = 0.0;
        self.out_current_burst_start = 0.0;
        self.out_current_burst_size = 0.0;

        // Incoming burst statistics
        self.in_bursts_packets.clear();
        self.in_bursts_bytes.clear();
        self.in_bursts_time.clear();
        self.in_current_burst = 0.0;
        self.in_current_burst_start = 0.0;
        self.in_current_burst_size = 0.0;
    }

    pub fn extract_packet_info(&mut self, chunk_time: u8) -> Result<Vec<Vec<PacketInfo>>, String> {
        let mut vec_of_chunks: Vec<Vec<PacketInfo>> = Vec::with_capacity(30_000);
        let mut current_chunk: Vec<PacketInfo> = Vec::with_capacity(1000);
        let mut current_time: f64 = 0.0;

        let mut cap = Capture::from_file(&self.pcap_file_path).map_err(|e| e.to_string())?;

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
            if self.fixed_ip.is_unspecified() {
                let src_ip = ipv6_packet.get_source();
                let dst_ip = ipv6_packet.get_destination();
                // whichever one has longer ipv6 name is the source, as the base station address is smaller
                if src_ip.to_string().len() > dst_ip.to_string().len() {
                    self.fixed_ip = src_ip;
                } else {
                    self.fixed_ip = dst_ip;
                }
            }

            let udp_packet = UdpPacket::new(ipv6_packet.payload());
            if udp_packet.is_none() {
                continue;
            }
            let udp_packet = udp_packet.unwrap();

            let timestamp =
                packet.header.ts.tv_sec as f64 + (packet.header.ts.tv_usec as f64 / 1_000_000.0);
            let size = (udp_packet.packet().len() - 8) as f64;

            if (timestamp - current_time) > (chunk_time as f64) {
                // only push the current chunk has more than 10 packets
                if current_chunk.len() > 10 {
                    vec_of_chunks.push(current_chunk);
                }
                current_chunk = Vec::with_capacity(1000);
                current_time = timestamp;
            }

            // Only grab one chunk. 
            // If you want to have more chunks, 
            // say if you are trying to break a large pcap into smaller chunks
            // You can uncomment these three lines
            if vec_of_chunks.len() > 0{
                break;
            }

            let is_incoming = self.fixed_ip == ipv6_packet.get_destination();

            current_chunk.push((timestamp, size, is_incoming));
        }

        // As stated before, last condition is if you want only one chunk
        // If multiple chunks are needed, remove the last condition
        if current_chunk.len() > 100 && (current_chunk[current_chunk.len() - 1].0 - current_chunk[0].0 > (chunk_time as f64 - 2.0)) && (vec_of_chunks.len() == 0)  {
            vec_of_chunks.push(current_chunk);
        }

        Ok(vec_of_chunks)
    }

    fn fill_data(&mut self, chunk: Vec<PacketInfo>) {
        let mut prev_ts = 0.0;

        for (ts, size, is_incoming) in chunk {
            // general statistics
            self.total_packets += 1.0;
            self.total_bytes += size;
            self.packet_size.push(size);
            if prev_ts != 0.0{
                self.packet_time.push(f64::max(ts - prev_ts, 0.0));
            }

            if is_incoming {
                self.total_packets_in += 1.0;
                self.total_bytes_in += size;
                self.packet_size_in.push(size);

                if prev_ts != 0.0{
                    self.packet_time_in.push(f64::max(ts - prev_ts, 0.0));
                }

                let bin = (size / self.bin_width as f64).round() as usize;
                self.in_packet_bins[bin] += 1;

                if self.in_current_burst == 0.0 {
                    self.in_current_burst_start = ts;
                }
                self.in_current_burst += 1.0;
                self.in_current_burst_size += size;

                if self.out_current_burst != 0.0 {
                    if self.out_current_burst > 1.0 {
                        self.out_bursts_packets.push(self.out_current_burst);
                        self.out_bursts_bytes.push(self.out_current_burst_size);
                        self.out_bursts_time.push(ts - self.out_current_burst_start);
                    }
                    self.out_current_burst = 0.0;
                    self.out_current_burst_start = 0.0;
                    self.out_current_burst_size = 0.0;
                }

            } else {
                self.total_packets_out += 1.0;
                self.total_bytes_out += size;
                self.packet_size_out.push(size);

                if prev_ts != 0.0{
                    self.packet_time_out.push(f64::max(ts - prev_ts, 0.0));
                }

                let bin = (size / self.bin_width as f64).round() as usize;
                self.out_packet_bins[bin] += 1;

                if self.out_current_burst == 0.0 {
                    self.out_current_burst_start = ts;
                }
                self.out_current_burst += 1.0;
                self.out_current_burst_size += size;


                if self.in_current_burst != 0.0 {
                    if self.in_current_burst > 1.0 {
                        self.in_bursts_packets.push(self.in_current_burst);
                        self.in_bursts_bytes.push(self.in_current_burst_size);
                        self.in_bursts_time.push(ts - self.in_current_burst_start);
                    }
                    self.in_current_burst = 0.0;
                    self.in_current_burst_start = 0.0;
                    self.in_current_burst_size = 0.0;
                }

            }

            prev_ts = ts;
        }
    }
    fn series_features(series: &Vec<f64>) -> [f64; 16] {
        let array = Array1::from_vec(series.iter().map(|&x| x.into()).collect());
        let mut features = [0.0; 16];

        features[0] = array.mean().unwrap_or(0.0);
        features[1] = array.std(0.0);
        features[2] = array.var(0.0);
        features[3] = array.kurtosis().unwrap_or(0.0) - 3.0; // fisher kurtosis
        features[4] = array.skewness().unwrap_or(0.0);
        features[5] = *array.min().unwrap_or(&0.0);
        features[6] = *array.max().unwrap_or(&0.0);

        let mut array = Data::new(series.iter().map(|&x| x.into()).collect::<Vec<f64>>());

        for i in (10..100).step_by(10) {
            features[i / 10 + 6] = array.percentile(i);
        }

        features
    }

    pub fn extract_stats(&mut self, vec_of_chunks: Vec<Vec<PacketInfo>>) -> (Vec<Vec<f64>>, Vec<Vec<usize>>) {
        let mut stats: Vec<Vec<f64>> = Vec::with_capacity(60);
        let mut stats_pl: Vec<Vec<usize>> = Vec::with_capacity(60);

        for chunk in vec_of_chunks {
            self.reset();
            self.fill_data(chunk);

            let mut chunk_stats: Vec<f64> = Vec::with_capacity(200);
            chunk_stats.push(self.total_packets);
            chunk_stats.push(self.total_packets_in);
            chunk_stats.push(self.total_packets_out);
            chunk_stats.push(self.total_bytes);
            chunk_stats.push(self.total_bytes_in);
            chunk_stats.push(self.total_bytes_out);

            chunk_stats.extend_from_slice(&Self::series_features(&self.packet_size));
            chunk_stats.extend_from_slice(&Self::series_features(&self.packet_size_in));
            chunk_stats.extend_from_slice(&Self::series_features(&self.packet_size_out));
            
            chunk_stats.extend_from_slice(&Self::series_features(&self.packet_time));
            chunk_stats.extend_from_slice(&Self::series_features(&self.packet_time_in));
            chunk_stats.extend_from_slice(&Self::series_features(&self.packet_time_out));

            chunk_stats.extend_from_slice(&Self::series_features(&self.out_bursts_packets));
            chunk_stats.extend_from_slice(&Self::series_features(&self.out_bursts_bytes));
            // chunk_stats.extend_from_slice(&Self::series_features(&self.out_bursts_time));

            chunk_stats.extend_from_slice(&Self::series_features(&self.in_bursts_packets));
            chunk_stats.extend_from_slice(&Self::series_features(&self.in_bursts_bytes));
            // chunk_stats.extend_from_slice(&Self::series_features(&self.in_bursts_time));

            stats.push(chunk_stats);

            let mut chunk_stats_pl: Vec<usize> = Vec::with_capacity(600);

            chunk_stats_pl.extend_from_slice(&self.in_packet_bins);
            chunk_stats_pl.extend_from_slice(&self.out_packet_bins);

            stats_pl.push(chunk_stats_pl);
        }

        (stats, stats_pl)
    }


    pub fn get_data(&mut self, chunk_time: u8) -> Result<(Vec<Vec<f64>>, Vec<Vec<usize>>), String> {
        let vec_of_chunks = self.extract_packet_info(chunk_time)?;
        let (stats, stats_pl) = self.extract_stats(vec_of_chunks);
        Ok((stats, stats_pl))
    }

    pub fn get_datetime(&self) -> String {
        self.datetime.to_string()
    }

    pub fn get_header() -> String {
        let mut header = String::new();
        header.push_str("total_packets,total_packets_in,total_packets_out,");
        header.push_str("total_bytes,total_bytes_in,total_bytes_out,");

        header.push_str(&Self::generate_series_header("packet_size"));
        header.push_str(&Self::generate_series_header("packet_size_in"));
        header.push_str(&Self::generate_series_header("packet_size_out"));

        header.push_str(&Self::generate_series_header("packet_time"));
        header.push_str(&Self::generate_series_header("packet_time_in"));
        header.push_str(&Self::generate_series_header("packet_time_out"));

        header.push_str(&Self::generate_series_header("out_burst_packets"));
        header.push_str(&Self::generate_series_header("out_burst_sizes"));
        // header.push_str(&Self::generate_series_header("out_burst_times"));

        header.push_str(&Self::generate_series_header("in_burst_packets"));
        header.push_str(&Self::generate_series_header("in_burst_sizes"));
        // header.push_str(&Self::generate_series_header("in_burst_times"));

        header.push_str("datetime,label");

        header
    }

    pub fn get_header_pl() -> String {
        let mut header = String::new();

        for i in 0..300 {
            header.push_str(&format!("pl_in_{},", i));
        }
        for i in 0..300 {
            header.push_str(&format!("pl_out_{},", i));
        }

        header.push_str("datetime,label");

        header
    }

    fn generate_series_header(series_name: &str) -> String {
        let mut header = String::new();
        header.push_str(&format!(
            "{}_mean,{}_std,{}_var,{}_kurtosis,{}_skew,{}_min,{}_max,",
            series_name,
            series_name,
            series_name,
            series_name,
            series_name,
            series_name,
            series_name
        ));

        for i in (10..100).step_by(10) {
            header.push_str(&format!("{}_p_{},", series_name, i));
        }
        header
    }
}
