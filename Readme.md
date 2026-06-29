# ViNET — Research Branch

This branch contains the full research codebase for the paper *"ViNET: Connecting the Unconnected using Video over LTE"*, including security analysis, ML-based traffic classification, and experiment data.

> [!NOTE]
> For the streamlined source code and deployment instructions, see the [`PROD`](../../tree/PROD) branch.


## Repository Structure

```
.
├── Core/                # Tunnel variants (see below)
├── Middle/              # Relay variants
├── Common/              # Shared utilities
├── Analysis/            # Security analysis & feature extraction
├── Data/                # Extracted feature CSVs
├── Tests/               # Automated testing framework
└── Makefile             # Build all variants
```


## Core Variants

The `Core/` directory contains multiple tunnel implementations used across different experiments. Each variant builds on the base tunnel with a specific behavior:

| File | Description |
|------|-------------|
| `Core.cpp` | Base tunnel — unencrypted packet interception and forwarding |
| `Encrypt.cpp` | Adds AES-CBC encryption via OpenSSL |
| `Encrypt.GCM.cpp` | Uses AES-GCM (authenticated encryption) instead of CBC |
| `EncryptNonBlock.cpp` | Non-blocking I/O variant of the encrypted tunnel — **used in paper experiments** |
| `EncryptDrop.cpp` | Encrypted tunnel with controlled packet drop simulation |
| `EncryptFMQ.cpp` | Encrypted tunnel using a fast message queue for inter-thread communication |
| `EncryptReplay.cpp` | Encrypted tunnel with packet replay capability |
| `EncryptReplayMap.cpp` | Replay variant using a map-based lookup for replayed packets |
| `CoreConstString.cpp` | Tunnel that appends a constant string payload (used for testing overhead) |
| `CoreMultiThread.cpp` | Multi-threaded tunnel with separate send/receive threads |

### Building All Variants

The included `Makefile` builds the primary binaries:

```bash
make
```

This compiles:
- `core` from `EncryptNonBlock.cpp`
- `core_append` from `CoreConstString.cpp`
- `netcat` from `Middle/Netcat.cpp`
- `router` from `Middle/Router.cpp`


## Security Analysis (`Analysis/`)

Scripts for evaluating whether a network observer can distinguish ViNET-tunneled traffic from standard ViLTE video calls.

### Dependencies

```bash
pip install -r Analysis/requirements.txt
```

For the Rust-based tools (`mpt_rs` and `rtp_loss`), build with:

```bash
cd Analysis/mpt_rs && cargo build --release
cd Analysis/rtp_loss && cargo build --release
```

### Pipeline

The analysis follows a three-stage pipeline:

#### 1. PCAP Chunking

Split raw packet captures into fixed-duration windows (10s–60s) for time-windowed analysis:

```bash
# Place .pcap files in the working directory, then:
bash Analysis/chunking.sh
```

This uses `editcap` to split each `.pcap` into 10-second chunks.

#### 2. Feature Extraction

Extract statistical features from chunked PCAPs. The primary tool is `mpt_rs` (Rust), which computes packet-level and payload-level features per chunk and outputs CSV files.

Run the full extraction pipeline across all ISPs and chunk lengths:

```bash
cd Data/forbidden_bit_60s
bash ../../Analysis/data_scripts/run_analysis.sh
```

This expects the following directory layout under the working directory:

```
<working_dir>/
├── airtel/
│   ├── vilte/    # .pcap files from standard ViLTE calls
│   └── vinet/    # .pcap files from ViNET-tunneled calls
├── jio/
│   ├── vilte/
│   └── vinet/
└── vi/
    ├── vilte/
    └── vinet/
```

There are also Python-based extraction scripts for additional features:

| Script | Purpose |
|--------|---------|
| `feature_extraction.py` | Extracts per-packet size, timing, and directionality features from IPv6/UDP PCAPs |
| `new_features.py` | Extended feature set — STUN/DTLS filtering, histogram bins, kurtosis, skew, inter-arrival statistics |
| `entropy.py` | Computes per-packet Shannon entropy and byte frequency distributions |
| `rtcp_jitter_calculation.py` | Extracts RTCP jitter and packet-type ratios from captured traffic |

#### 3. Model Training & Classification

Train classifiers (XGBoost, Random Forest, Decision Tree) to distinguish ViLTE from ViNET traffic using stratified 7-fold cross-validation:

```bash
python Analysis/model_training.py
```

This produces:
- ROC curves and AUC scores per ISP and chunk length
- Feature importance rankings
- Confusion matrices and precision/recall/F1 metrics

### Rust Tools

| Tool | Purpose |
|------|---------|
| `mpt_rs` | High-performance PCAP feature extractor — computes packet-level and payload-level stats, outputs CSV |
| `rtp_loss` | RTP packet loss and sequence analysis from PCAPs |


## Experiment Data (`Data/`)

Pre-extracted feature CSVs ready for model training, organized by experiment and ISP:

```
Data/
├── forbidden_bit_60s/         # 60-second capture experiments
│   └── features/
│       ├── airtel/            # Airtel carrier
│       │   ├── chunks_10s/    # Features at 10s granularity
│       │   ├── chunks_10s_pl/ # Payload-level features at 10s
│       │   ├── ...
│       │   └── chunks_60s_pl/
│       ├── jio/               # Jio carrier
│       └── vi/                # Vi carrier
└── one_transfer/              # Single file-transfer experiments
    └── features/
        └── jio/
```

Each directory contains paired CSVs: `<isp>_vilte.csv` (label 0) and `<isp>_vinet.csv` (label 1).


