from scapy.all import rdpcap, IPv6, UDP
from scipy.stats import kurtosis, skew
from tqdm import tqdm
import numpy as np
import pandas as pd
import pathlib
import re
import collections
from datetime import datetime
import warnings
import argparse

warnings.filterwarnings("ignore")

class PacketAnalyzer:
    """Class to analyze network packets from pcap files."""
    
    # Protocol constants
    STUN_DTLS_SIGNATURES = [
        (0, 1), (1, 1), (1, 17), (0, 2), 
        (1, 2), (1, 18), (1, 21), (22,)
    ]
    
    def __init__(self, pcap_file_path: str, bin_width: int = 5):
        """
        Initialize the PacketAnalyzer with a pcap file.
        
        Args:
            pcap_file_path: Path to the pcap file to analyze
            bin_width: Width of histogram bins for packet sizes
        """
        self.pcap_file_path = pcap_file_path
        self.bin_width = bin_width
        
        # Packet statistics
        self.total_packets = 0
        self.total_packets_in = 0
        self.total_packets_out = 0
        
        # Byte statistics
        self.total_bytes = 0
        self.total_bytes_in = 0
        self.total_bytes_out = 0
        
        # Size statistics
        self.packet_sizes = []
        self.packet_sizes_in = []
        self.packet_sizes_out = []
        
        # Bin dictionaries for histograms
        self.out_packet_bins = {i: 0 for i in range(0, 10000, bin_width)}
        self.in_packet_bins = {i: 0 for i in range(0, 10000, bin_width)}
        
        # Timing statistics
        self.packet_times = []
        self.packet_times_in = []
        self.packet_times_out = []
        self.abs_times_out = []
        
        # Outgoing burst statistics
        self.out_bursts_packets = []
        self.out_burst_sizes = []
        self.out_burst_times = []
        self.out_current_burst = 0
        self.out_current_burst_start = 0
        self.out_current_burst_size = 0
        
        # Incoming burst statistics
        self.in_bursts_packets = []
        self.in_burst_sizes = []
        self.in_burst_times = []
        self.in_current_burst = 0
        self.in_current_burst_start = 0
        self.in_current_burst_size = 0
        
        # Connection info
        self.source_ip = None
        self.dest_ip = None
        
    def process_packets(self):
        """Process all packets in the pcap file and collect statistics."""
        packets = rdpcap(self.pcap_file_path)
        self.prev_ts = 0
        ip_initialized = False
        
        for pkt in packets:
            if not (pkt.haslayer(IPv6) and pkt.haslayer(UDP)):
                continue
                
            ts = float(pkt.time)
            
            if not ip_initialized:
                self.source_ip = pkt[IPv6].src
                self.dest_ip = pkt[IPv6].dst
                ip_initialized = True
            
            packet_size = len(pkt)
            self._update_general_stats(packet_size)
            
            is_incoming = (pkt[IPv6].src == self.dest_ip)
            if is_incoming:
                self._handle_incoming_packet(packet_size, ts)
            else:
                self._handle_outgoing_packet(packet_size, ts)
            
            if self.prev_ts != 0:
                ts_difference = max(0, ts - self.prev_ts)
                self.packet_times.append(ts_difference * 1000)
            
            self.prev_ts = ts
    
    def _update_general_stats(self, packet_size: int):
        """Update general packet statistics."""
        self.total_packets += 1
        self.total_bytes += packet_size
        self.packet_sizes.append(packet_size)
    
    def _handle_incoming_packet(self, packet_size: int, ts: float):
        """Process an incoming packet."""
        self.total_packets_in += 1
        self.total_bytes_in += packet_size
        self.packet_sizes_in.append(packet_size)
        
        if self.prev_ts != 0:
            ts_difference = max(0, ts - self.prev_ts)
            self.packet_times_in.append(ts_difference * 1000)

        # TODO: Uncomment this later
        # Update size histogram
        # binned = np.round(packet_size / self.bin_width) * self.bin_width
        # self.in_packet_bins[binned] += 1
        
        # Handle burst traffic
        if self.out_current_burst != 0:
            if self.out_current_burst > 1:
                self.out_bursts_packets.append(self.out_current_burst)
                self.out_burst_sizes.append(self.out_current_burst_size)
                self.out_burst_times.append(ts - self.out_current_burst_start)
            self.out_current_burst = 0
            self.out_current_burst_size = 0
            self.out_current_burst_start = 0
            
        if self.in_current_burst == 0:
            self.in_current_burst_start = ts
        self.in_current_burst += 1
        self.in_current_burst_size += packet_size
    
    def _handle_outgoing_packet(self, packet_size: int, ts: float):
        """Process an outgoing packet."""
        self.total_packets_out += 1
        self.total_bytes_out += packet_size
        self.packet_sizes_out.append(packet_size)
        self.abs_times_out.append(ts)
        
        if self.prev_ts != 0:
            ts_difference = max(0, ts - self.prev_ts)
            self.packet_times_out.append(ts_difference * 1000)

        # TODO: Uncomment this later
        # Update size histogram
        # binned = np.round(packet_size / self.bin_width) * self.bin_width
        # self.out_packet_bins[binned] += 1
        
        # Handle burst tracking
        if self.in_current_burst != 0:
            if self.in_current_burst > 1:
                self.in_bursts_packets.append(self.in_current_burst)
                self.in_burst_sizes.append(self.in_current_burst_size)
                self.in_burst_times.append(ts - self.in_current_burst_start)
            self.in_current_burst = 0
            self.in_current_burst_size = 0
            self.in_current_burst_start = 0
            
        if self.out_current_burst == 0:
            self.out_current_burst_start = ts
        self.out_current_burst += 1
        self.out_current_burst_size += packet_size


class FeatureExtractor:
    """Class to extract features from packet data."""
    
    def __init__(self, packet_analyzer: PacketAnalyzer):
        """
        Initialize the FeatureExtractor with a PacketAnalyzer instance.
        
        Args:
            packet_analyzer: An instance of PacketAnalyzer
        """
        self.packet_analyzer = packet_analyzer

        self.feats = {}

        self.pl_feats = {}

    def _global_stats(self):
        self.feats["total_packets"] = self.packet_analyzer.total_packets
        self.feats["total_packets_in"] = self.packet_analyzer.total_packets_in
        self.feats["total_packets_out"] = self.packet_analyzer.total_packets_out
        self.feats["total_bytes"] = self.packet_analyzer.total_bytes
        self.feats["total_bytes_in"] = self.packet_analyzer.total_bytes_in
        self.feats["total_bytes_out"] = self.packet_analyzer.total_bytes_out

    def _extract_series_features(self, series, feature_name):
        if not series or len(series) == 0:
            self.feats[feature_name + "_mean"] = 0
            self.feats[feature_name + "_median"] = 0
            self.feats[feature_name + "_std"] = 0
            self.feats[feature_name + "_var"] = 0
            self.feats[feature_name + "_kurtosis"] = 0
            self.feats[feature_name + "_skew"] = 0
            self.feats[feature_name + "_min"] = 0
            self.feats[feature_name + "_max"] = 0

            for i in range(10, 100, 10):
                self.feats[feature_name + f"_p_{i}"] = 0
            return

        self.feats[feature_name + "_mean"] = np.mean(series)
        self.feats[feature_name + "_median"] = np.median(series)
        self.feats[feature_name + "_std"] = np.std(series)
        self.feats[feature_name + "_var"] = np.var(series)
        self.feats[feature_name + "_kurtosis"] = kurtosis(series)
        self.feats[feature_name + "_skew"] = skew(series)
        self.feats[feature_name + "_min"] = np.min(series)
        self.feats[feature_name + "_max"] = np.max(series)

        for i in range(10, 100, 10):
            self.feats[feature_name + f"_p_{i}"] = np.percentile(series, i)
    
    def _series_stats(self):
        """Extract statistics from packet size and timing series."""
        
        # packet sizes
        self._extract_series_features(self.packet_analyzer.packet_sizes, "packet_size")
        self._extract_series_features(self.packet_analyzer.packet_sizes_in, "packet_size_in")
        self._extract_series_features(self.packet_analyzer.packet_sizes_out, "packet_size_out")

        # packet times
        self._extract_series_features(self.packet_analyzer.packet_times, "packet_time")
        self._extract_series_features(self.packet_analyzer.packet_times_in, "packet_time_in")
        self._extract_series_features(self.packet_analyzer.packet_times_out, "packet_time_out")
        
        # outgoing burst 
        self._extract_series_features(self.packet_analyzer.out_bursts_packets, "out_burst_packets")
        self._extract_series_features(self.packet_analyzer.out_burst_sizes, "out_burst_sizes")
        self._extract_series_features(self.packet_analyzer.out_burst_times, "out_burst_times")

        # incoming burst
        self._extract_series_features(self.packet_analyzer.in_bursts_packets, "in_burst_packets")
        self._extract_series_features(self.packet_analyzer.in_burst_sizes, "in_burst_sizes")
        self._extract_series_features(self.packet_analyzer.in_burst_times, "in_burst_times")

    def extract_features(self):
        #extract the features
        self._global_stats()
        self._series_stats()

        dt = self._get_datetime_from_filename(self.packet_analyzer.pcap_file_path)
        self.feats["datetime"] = dt.isoformat()

        self._replace_nans()


    def extract_features_pl(self):
        od_dict_in_bin = collections.OrderedDict(sorted(self.packet_analyzer.in_packet_bins.items(), key=lambda t: float(t[0])))
        od_dict_out_bin = collections.OrderedDict(sorted(self.packet_analyzer.out_packet_bins.items(), key=lambda t: float(t[0])))

        in_bin_list = [od_dict_in_bin[i] for i in od_dict_in_bin]
        out_bin_list = [od_dict_out_bin[i] for i in od_dict_out_bin]

        for i, b in enumerate(in_bin_list):
            self.pl_feats[f"pl_in_{i}"] = b
        for i, b in enumerate(out_bin_list):
            self.pl_feats[f"pl_out_{i}"] = b
        
        dt = self._get_datetime_from_filename(self.packet_analyzer.pcap_file_path)
        self.pl_feats["datetime"] = dt.isoformat()

        self._replace_nans()

    def _replace_nans(self):
        """Replace NaN values in the features dictionary with 0."""
        for key, value in self.feats.items():
            if isinstance(value, float) and np.isnan(value):
                self.feats[key] = 0
        for key, value in self.pl_feats.items():
            if isinstance(value, float) and np.isnan(value):
                self.pl_feats[key] = 0



    def _get_datetime_from_filename(self, filename):
        pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)'
        match = re.search(pattern, filename)
        if match:
            datetime_str = match.group(1)
            dt = datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%S.%f")
            return dt
        else:
            raise ValueError("No date found in filename")

    def get_header(self) -> str:
        """Get the header for the features, as row seperated by commas."""
        return ",".join(self.feats.keys())
    
    def get_features(self) -> str:
        """Get the features as a string, with values separated by commas."""
        return ",".join([str(v) for v in self.feats.values()])
    
    def get_pl_header(self) -> str:
        """Get the header for the packet length features, as row separated by commas."""
        return ",".join(self.pl_feats.keys())

    def get_pl_features(self) -> str:
        """Get the features as a string, with values separated by commas."""
        return ",".join([str(v) for v in self.pl_feats.values()])


def process_pcaps(directory, output_file_feature_set_1, output_file_feature_set_2, true_label):
    features_pl = pd.DataFrame()
    features_summary = pd.DataFrame()

    for file in list(pathlib.Path(directory).glob("*.pcap")):
        print("Processing file:", file)  
        packet_analyzer = PacketAnalyzer(str(file.resolve()))
        feature_extractor = FeatureExtractor(packet_analyzer)
        feature_extractor.packet_analyzer.process_packets()
        # feature_extractor.extract_features_pl()
        feature_extractor.extract_features()

        # if features is an empty df, create it with the first row
        # if features_pl.empty:
        #     features_pl = pd.DataFrame([feature_extractor.pl_feats])
        # else:
        #     features_pl = pd.concat([features_pl, pd.DataFrame([feature_extractor.pl_feats])], ignore_index=True)
        
        if features_summary.empty:
            features_summary = pd.DataFrame([feature_extractor.feats])
        else:
            features_summary = pd.concat([features_summary, pd.DataFrame([feature_extractor.feats])], ignore_index=True)
    
    # if not features_pl.empty:
    #     features_pl["label"] = true_label
    #     features_pl.to_csv(output_file_feature_set_2, index=False)
    
    if not features_summary.empty:
        features_summary["label"] = true_label
        features_summary.to_csv(output_file_feature_set_1, index=False)
        

    else:
        print("No PCAP files found in the directory")

def main():
    parser = argparse.ArgumentParser(description="Extract features from PCAP files")
    parser.add_argument("-d", "--directory", help="Directory containing PCAP files")
    parser.add_argument("--output_feature_set_1", help="Output CSV file for feature set 1")
    parser.add_argument("--output_feature_set_2", help="Output CSV file for feature set 2", default=None)
    parser.add_argument("-t", "--true_label", help="True label of the PCAP files")

    args = parser.parse_args()

    process_pcaps(args.directory, args.output_feature_set_1, args.output_feature_set_2, args.true_label)


if __name__ == "__main__":
    main()