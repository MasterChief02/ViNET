from scapy.all import *

packets = rdpcap ("wifi.pcap")

for p in packets:
    if p.haslayer(ESP):
        print(p[ESP].spi)