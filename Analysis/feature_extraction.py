from scapy.all import rdpcap, IPv6, UDP, Packet
from tqdm import tqdm
from datetime import datetime
import pandas as pd
import re
import pathlib
import argparse

BOTH_DIRECTION: int = 0
INCOMING_DIRECTION: int = 1
OUTGOING_DIRECTION: int = 2

def extract_packet_info(pcap_file, cutoff: int = 0):
    packets = rdpcap(pcap_file)
    packets_both = []
    fixed_ip = None
    packets_incoming = []
    packets_outgoing = []
    starting_ts = 0
    if packets:
        starting_ts = packets[0].time

    for pkt in packets:
        pkt: Packet
        if pkt.haslayer(IPv6) and pkt.haslayer(UDP):
            if fixed_ip is None:
                # the bigger IP address is fixed
                src_ip_str = str(pkt[IPv6].src)
                dst_ip = str(pkt[IPv6].dst)
                if src_ip_str > dst_ip:
                    fixed_ip = pkt[IPv6].src
                else:
                    fixed_ip = pkt[IPv6].dst

            size = len(pkt["UDP"].payload)
            timestamp = float(pkt.time)

            if timestamp - starting_ts > cutoff:
                break

            packets_both.append((timestamp, BOTH_DIRECTION, size))

            if pkt[IPv6].src == fixed_ip:
                packets_outgoing.append((timestamp, OUTGOING_DIRECTION, size))
            elif pkt[IPv6].dst == fixed_ip:
                packets_incoming.append((timestamp, INCOMING_DIRECTION, size))

    return packets_both, packets_incoming, packets_outgoing

def compute_stats(packets, direction, time_window:int = 10):
    if not packets:
        return pd.DataFrame()
    

    df = pd.DataFrame(packets, columns=["timestamp", "direction", "size"])

    df["iat"] = df["timestamp"].diff().fillna(0)

    size_stats = df["size"].agg(
        count="count",
        total_bytes="sum",
        min_size="min",
        max_size="max",
        avg_size="mean",
        std_size="std",
    ).infer_objects(copy=False).fillna(0).to_frame()

    iat_stats = df["iat"].agg(
        min_iat="min",
        max_iat="max",
        avg_iat="mean",
        std_iat="std",
    ).infer_objects(copy=False).fillna(0).to_frame()

    result = size_stats.merge(iat_stats, left_index=True, right_index=True)
    result["direction"] = direction
    result = result.reset_index()

    return result


def get_datetime_from_filename(filename):
    pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)'
    match = re.search(pattern, filename)
    if match:
        datetime_str = match.group(1)
        dt = datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%S.%f")
        return dt
    else:
        raise ValueError("No date found in filename")



def process_pcaps(directory, output_file, true_label, time_window:int = 10):
    all_stats = []

    for file in tqdm(pathlib.Path(directory).glob("*.pcap"), desc="Processing PCAP files"):
        # extract datetime from filename
        # example file name: client-ZD2222HWXH-2025-03-05T14:41:48.241895-airtel-do_nothing.pcap
        dt = get_datetime_from_filename(file.name)

        packets_both, packets_incoming, packets_outgoing = extract_packet_info(file.as_posix(), time_window)
        stats_both = compute_stats(packets_both, BOTH_DIRECTION, time_window)
        stats_incoming = compute_stats(packets_incoming, INCOMING_DIRECTION, time_window)
        stats_outgoing = compute_stats(packets_outgoing, OUTGOING_DIRECTION, time_window)

        stats = pd.concat([stats_both, stats_incoming, stats_outgoing], ignore_index=True)

        stats["label"] = true_label
        stats["datetime"] = dt.isoformat()
        
        all_stats.append(stats)

    if all_stats:
        final_df = pd.concat(all_stats, ignore_index=True)
        final_df.to_csv(output_file, index=False)
    else:
        print("No PCAP files found in the directory")


def main():
    parser = argparse.ArgumentParser(description="Extract features from PCAP files")
    parser.add_argument("-d", "--directory", help="Directory containing PCAP files")
    parser.add_argument("-o", "--output_file", help="Output CSV file")
    parser.add_argument("-t", "--true_label", help="True label of the PCAP files")
    parser.add_argument("-w", "--time_window", type=int, default=10, help="Time window for statistics")

    args = parser.parse_args()

    process_pcaps(args.directory, args.output_file, args.true_label)


if __name__ == "__main__":
    main()