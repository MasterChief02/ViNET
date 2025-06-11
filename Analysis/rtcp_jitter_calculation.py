from scapy.all import rdpcap, UDP
from tqdm import tqdm
import time
import pathlib
import argparse
import socket
import numpy as np
import matplotlib.pyplot as plt
from scapy.contrib.rtcp import RTCP, ReceptionReport

def count_rtcp_packets(pcap_file):
    packets = rdpcap(pcap_file)
    
    udp_cnts = []
    rtcp_cnts = []

    curr_udp_cnt = 0
    curr_rtcp_cnt = 0


    if packets:
        start_time = packets[0].time
    else:
        return []    


    for packet in packets:
        if UDP in packet:
            if packet.time - start_time > 1:
                udp_cnts.append(curr_udp_cnt)
                rtcp_cnts.append(curr_rtcp_cnt)
                start_time = packet.time

            curr_udp_cnt += 1
            payload = bytes(packet[UDP].payload)
            version = (payload[0] >> 6) & 0x03
            packet_type = payload[1] & 0xFF
            # RTCP packet types are typically between 200-204
            if version == 2 and 200 <= packet_type <= 204:
                curr_rtcp_cnt += 1

    percentage_rtcp = np.array([np.round(rtcp_cnt * 100 / udp_cnt, 4) if udp_cnt > 0 else 0 for rtcp_cnt, udp_cnt in zip(rtcp_cnts, udp_cnts)])

    # exclude the first 10 second as it may not have a full second of data
    # percentage_rtcp = percentage_rtcp[10:]

    return percentage_rtcp

def get_jitter(pcap_file):
    packets = rdpcap(pcap_file)
    jitter_by_second = {}
    
    if packets:
        start_time = packets[0].time
    else:
        return []

    for packet in packets:
        if UDP in packet:
            payload = bytes(packet[UDP].payload)
            version = (payload[0] >> 6) & 0x03
            packet_type = payload[1] & 0xFF
            if version == 2 and 200 <= packet_type <= 204:
                try:
                    rtcp_pkt = RTCP(payload)
                    if ReceptionReport in rtcp_pkt:
                        recpt = rtcp_pkt[ReceptionReport]
                        jitter_val = recpt.interarrival_jitter / 90

                        # Group jitter by the integer second offset
                        second_offset = int(packet.time - start_time)
                        if second_offset not in jitter_by_second:
                            jitter_by_second[second_offset] = []
                        jitter_by_second[second_offset].append(jitter_val)
                except Exception:
                    continue

    # Compute average jitter per second
    avg_jitter_per_second = np.zeros(max(jitter_by_second.keys()) + 1)
    for second in sorted(jitter_by_second.keys()):
        avg_jitter_per_second[second] = np.mean(jitter_by_second[second])
    
    return avg_jitter_per_second

def process_pcaps(directory, jitter):
    files = list(pathlib.Path(directory).glob("*.pcap"))
    if not files:
        print("No PCAP files found in the directory")
        return

    rtcp_none = True 
    jitter_none = True
    rtcp_percentages = None
    jitter_scores = None

    for i, file in enumerate(tqdm(files, desc="Processing PCAP files")):
        if rtcp_none:
            rtcp_percentages = count_rtcp_packets(file.as_posix())
            rtcp_none = False
        else:
            # find which one has the lesser length, add up to that length
            temp_rtcp_percentages = count_rtcp_packets(file.as_posix())
            min_len = min(len(rtcp_percentages), len(temp_rtcp_percentages))
            rtcp_percentages = np.add(rtcp_percentages[:min_len], temp_rtcp_percentages[:int(min_len)])
        
        if jitter_none:
            jitter_scores = get_jitter(file.as_posix())
            jitter_none = False
        else:
            # find which one has the lesser length, add up to that length
            temp_jitter_scores = get_jitter(file.as_posix())
            min_len = min(len(jitter_scores), len(temp_jitter_scores))
            jitter_scores = np.add(jitter_scores[:min_len], temp_jitter_scores[:min_len])

    jitter_scores = jitter_scores / len(files)
    rtcp_percentages = rtcp_percentages / len(files)

    # plot RTCP percentages
    plt.plot(rtcp_percentages)
    plt.xlabel("Time (s)")
    plt.ylabel("RTCP (%)")
    plt.title("RTCP percentage per second")
    plt.ylim(0, 20)
    plt.grid(True)
    plt.show()

    # plot jitter scores
    plt.plot(jitter_scores)
    plt.xlabel("Time (s)")
    plt.ylabel("Jitter (ms)")
    plt.title("Jitter per second")
    plt.ylim(0, 30)
    plt.grid(True)
    plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Count RTCP packets in PCAP files")
    parser.add_argument("-d", "--directory", help="Directory containing PCAP files")
    parser.add_argument("-j", "--jitter", help="Calculate jitter", action="store_true")

    args = parser.parse_args()
    process_pcaps(args.directory, args.jitter)