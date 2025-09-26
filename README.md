# Beagl3

A hybrid **network packet sniffer** and **feature extractor** built for **Linux systems**. This tool captures live network traffic using **C++ (libpcap)** and extracts useful features via **Python (Scapy)** into a structured `.csv` file for cybersecurity analysis, anomaly detection, or machine learning applications.

---

## Why I Built This

I created this project to strengthen my understanding of **network protocols**, **packet capture**, and **feature engineering** for cybersecurity. It allowed me to gain hands-on experience in:

- Capturing and dissecting raw packets with `libpcap`
- Handling real-time data and saving it for post-analysis
- Extracting ML-relevant features for intrusion detection systems (IDS)
- Cross-language development using C++ and Python

---

## Features

### Real-Time Packet Sniffing (C++)
- Captures live packets using `libpcap`
- Saves packets to a `.pcap` file
- Clean termination with `Ctrl+C` ensuring safe write
- Customizable CLI options:
  - Interface: `-i eth0`
  - Duration: `-t 30`
  - Filters: `-f "tcp or udp"`

### Post-Capture Feature Extraction (Python)
- Processes `.pcap` file using **Scapy**
- Extracts:
  - Timestamps, IPs, MACs, Ports, TTL, Length
  - TCP Flags, ICMP Type/Code, Protocols
  - Derived features:
    - `protocol_type_tcp`, `protocol_type_udp`, `protocol_type_icmp`
    - `flag_S0`, `flag_SF`, `flag_REJ`, `flag_RSTO`, `flag_RSTR`
    - `service_http`, `service_ssh`, `service_private`, etc.

---

## How It Works

### 1. Compile & Run the Sniffer (C++)

```bash
g++ sniffer.cpp -o sniffer -lpcap
sudo ./sniffer -i eth0 -t 30 -f "tcp or udp"
```

The program saves packets to a `.pcap` file and automatically invokes the Python script for processing.

### 2. Feature Extraction (Python)

```bash
python3 convert.py output.pcap
```

The output `.csv` will contain structured packet data for further use.

---

## How to Use This Tool

> **Linux-only support**: This tool is developed, tested, and optimized for **Linux systems**. It uses `libpcap` for packet capture and Scapy for feature extraction—both of which are fully supported on Linux.

### Requirements:

```bash
# For packet capture
sudo apt install libpcap-dev

# For feature extraction
pip install scapy
```

### Usage Steps:

1. Clone the repo and navigate to it.
2. Compile the sniffer:
   ```bash
   g++ sniffer.cpp -o sniffer -lpcap
   ```
3. Run the sniffer with elevated privileges:
   ```bash
   sudo ./sniffer -i eth0 -t 60 -f "tcp or udp"
   ```
4. The packets will be saved and converted to `.csv` automatically by `convert.py`.

---

## Limitations

- Requires root privileges (`sudo`) for capturing traffic.
- Linux-only due to dependence on `libpcap`.
- No real-time classification or alerting (currently logging only).
- Only extracts features observable from raw packet headers (no session-based metrics).

---

## Pros

- Modular design: Separate capture and analysis stages
- Feature-rich: Includes protocol, flags, service-based enrichment
- Lightweight and fast
- Educational value: Learn low-level packet internals and feature engineering

---

## Educational Benefits

This project was a practical exercise in:

- **System programming** with `libpcap`
- **Packet analysis** using Scapy
- **Feature extraction** for ML/IDS models (like NSL-KDD)
- **Security data engineering** and data wrangling

Perfect for students, beginners in network security, or anyone preparing for cybersecurity competitions.

---

## Contributions Welcome

Want to add more protocol support? Real-time threat detection? Port it to BSD?  
**Feel free to fork, suggest changes, or create a pull request.**  
All contributions are welcome and encouraged!

---

## Output Example

A `.csv` file containing rows like:

```csv
Timestamp,MAC Src,MAC Dst,IP Src,IP Dst,Protocol,Src Port,Dst Port,...
protocol_type_tcp,protocol_type_udp,protocol_type_icmp,
flag_S0,flag_SF,flag_REJ,flag_RSTO,flag_RSTR,
service_http,service_ftp_data,service_private,...
```

---

## Reach me
  
🔗 [LinkedIn](https://linkedin.com/in/debankan-mullick)
🔗 [Instagram](https://instagram.com/senor_debankan)
