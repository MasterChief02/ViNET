# ViNET

This repository holds the code for the paper **ViNET: Connecting the Unconnected using Video over LTE**


> [!NOTE]
> This is the **production** branch. It contains the streamlined source code and testing framework.
> For the full research codebase — including security analysis, feature extraction, plotting notebooks, and experiment data — see the [`master`](../../tree/master) branch.


## Architecture

ViNET deploys two cooperating components on a pair of rooted Android devices:

| Component | Role | Entry Point |
|-----------|------|-------------|
| **Core** (Tunnel) | Packet interception via `NFQUEUE`, AES encryption (OpenSSL), and forwarding over a TCP control/data channel | `ViNET/Core/Core.cpp` |
| **Middle** (Relay) | NAT translation and packet routing between the client network and the internet via raw sockets | `ViNET/Middle/Router.cpp` |

```
┌──────────┐     WiFi      ┌──────────────────┐    LTE (ViLTE)     ┌──────────────────┐     Internet
│  Client  │◄────────────► │  Android Client  │◄──────────────────►│  Android Peer    │◄──────────────►
│ (Laptop) │               │  Core + Router   │                    │  Core + Router   │
└──────────┘               └──────────────────┘                    └──────────────────┘
```


## Repository Structure

```
.
├── ViNET/
│   ├── Core/            # Tunnel — interception, encryption, forwarding
│   ├── Middle/          # Relay  — NAT, routing, raw socket I/O
│   └── Common/          # Shared utilities (Logger)
└── Tests/               # Automated testing framework
```


## Prerequisites

1. Two **rooted Android devices** with ViLTE support.
2. Active **SIM cards** on both devices with a carrier plan that supports ViLTE (Video over LTE) calling.
3. **Verify video calling works** — place a ViLTE video call between the two devices over the carrier network before proceeding. If this call does not connect, ViNET will not function.


## Quick Start

### 1. Device Setup

Install [Termux](https://termux.dev) on both devices, then enable the required repos and install dependencies:

```bash
pkg install root-repo x11-repo
pkg install libnetfilter-queue libnetfilter-queue-static
```

### 2. Build

Clone the repo and push the source to `/data/local/tmp` on each device. Compile with:

```bash
aarch64-linux-android-g++ ViNET/Core/Core.cpp -o core -lnetfilter_queue -lssl -lcrypto
aarch64-linux-android-g++ ViNET/Middle/Router.cpp -o router -lpthread
```

### 3. Network Topology

- Enable **WiFi hotspot** on the Android Client. Connect the client laptop to it.
- Connect the **Android Peer** to the internet via WiFi.
- Identify the LTE interface on each device — look for the `rmnet_data<n>` interface carrying an IPv6 address:

```bash
ip -6 addr show | grep rmnet_data
```

### 4. Configure iptables

**Android Client** — replace `<n>` with your interface number from the previous step:

```bash
ip6tables -t mangle -A INPUT  -i rmnet_data<n> -p UDP -j NFQUEUE --queue-num 5
ip6tables -t mangle -A OUTPUT -o rmnet_data<n> -p UDP -j NFQUEUE --queue-num 6
```

**Android Peer:**

```bash
ip6tables -t mangle -A INPUT  -i rmnet_data<n> -p UDP -j NFQUEUE --queue-num 5
ip6tables -t mangle -A OUTPUT -o rmnet_data<n> -p UDP -j NFQUEUE --queue-num 6

# wlan0 is the Peer's WiFi interface connected to the internet.
# MASQUERADE rewrites the source IP of tunneled packets so they appear to
# originate from the Peer, allowing return traffic to route back correctly.
iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE

# Suppress ICMP "destination unreachable" responses on the WiFi interface
# to prevent the kernel from interfering with tunneled connections.
iptables -A OUTPUT -o wlan0 -p icmp --icmp-type 3 -j REJECT
```

### 5. Launch

Start Core on **both** devices (use each device's own `rmnet_data<n>` IPv6 address):

```bash
./core <self_ipv6>
```

Start the Router — replace `<laptop_ip>` with the laptop's WiFi IP:

```bash
# Android Client (mode 0 = client)
./router 0 <laptop_ip>

# Android Peer (mode 1 = server)
# The last argument is the Peer's WiFi gateway IP — the Router uses it for
# source NAT so that tunneled packets are routed correctly to the internet.
# Find it with: ip route show default dev wlan0
./router 1 <laptop_ip> 192.168.0.1
```

### 6. Connect

Initiate a ViLTE video call from the Android Client to the Android Peer. Once the call is connected, the laptop has internet access through the tunnel.


## Testing

See [`Tests/README.md`](Tests/README.md) for the automated testing framework, covering web browsing, throughput (iperf3), ViLTE analysis, file transfers, and application-level benchmarks.
