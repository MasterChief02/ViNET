from scapy.all import rdpcap, UDP, IPv6
from tqdm import tqdm
import pathlib
import argparse
import numpy as np
import matplotlib.pyplot as plt
from scapy.contrib.rtcp import RTCP, ReceptionReport

def byte_count(pcap_file):
    packets = rdpcap(pcap_file)

    byte_count_bins = np.zeros(256)

    entropy_values = np.zeros(len(packets))


    for idx, packet in enumerate(packets):
        if packet.haslayer(IPv6) and packet.haslayer(UDP):
            
            payload = bytes(packet[UDP].payload)

            if len(payload) < 400:
                continue

            data_arr = np.frombuffer(payload, dtype=np.uint8)
            values, counts = np.unique(data_arr, return_counts=True)
            byte_count_bins[values] += counts

            probability = counts / np.sum(counts)

            entropy = -np.sum(probability * np.log2(probability + 1e-10))  # Add small value to avoid log(0)
            entropy_values[idx] = entropy
            
        
    return byte_count_bins

def calculate_entropy(pcap_file):
    packets = rdpcap(pcap_file)


    entropy_values = np.zeros(len(packets))


    for idx, packet in enumerate(packets):
        if packet.haslayer(IPv6) and packet.haslayer(UDP):
            
            payload = bytes(packet[UDP].payload)
            data_arr = np.frombuffer(payload, dtype=np.uint8)
            _, counts = np.unique(data_arr, return_counts=True)
            probability = counts / np.sum(counts)
            entropy = -np.sum(probability * np.log2(probability + 1e-10))  # Add small value to avoid log(0)
            entropy_values[idx] = entropy
            
        
    return entropy_values 


def process_pcaps(directory, title, red_color):
    files = list(pathlib.Path(directory).glob("*.pcap"))
    if not files:
        print("No PCAP files found in the directory")
        return

    byte_count_bins = np.zeros(256)    
    entropy_arr = []


    for i, file in enumerate(tqdm(files, desc="Processing PCAP files")):
        byte_count_bins += byte_count(file.as_posix())
        entropy_arr.extend(calculate_entropy(file.as_posix()))

    
    byte_count_bins = byte_count_bins / np.sum(byte_count_bins) * 100

    # dump count to file
    np.savetxt(f"numbers/{directory.replace('/', '_')}_byte_count.txt", byte_count_bins, fmt='%.2f')

    np.savetxt(f"numbers/{directory.replace('/', '_')}_entropy.txt", entropy_arr, fmt='%.2f')    


    print(np.mean(entropy_arr))
    print(np.std(entropy_arr))
    
    plt.figure(figsize=(10, 6))
    if red_color:
        plt.bar(range(256), byte_count_bins, color='tab:orange', alpha=0.7, edgecolor=None, linewidth=0, width=1)
    else:
        plt.bar(range(256), byte_count_bins, alpha=0.7, edgecolor=None, linewidth=0, width=1)
    plt.xlim(0, 255)
    plt.ylim(0, 2)

    plt.title(f'Distribution of Byte Values for {title}')
    plt.grid(alpha=0.3, zorder=0)
    plt.xlabel('Byte Value')
    plt.ylabel('Percentage of Total Bytes')
    plt.tight_layout()
    plt.savefig(f"{title}_byte_distribution.pdf")




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate entropy and byte distribution in PCAP files")
    parser.add_argument("-d", "--directory", help="Directory containing PCAP files")
    parser.add_argument("-t", "--title", help="Title for the plot")
    parser.add_argument("-r", help="Graph color being regular or red", action="store_true")

    args = parser.parse_args()
    process_pcaps(args.directory, args.title, args.r)