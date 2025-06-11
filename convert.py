import pyshark
import csv
import sys
from datetime import datetime

if len(sys.argv) != 2:
    print("Usage: python3 convert.py <input.pcap>")
    sys.exit(1)

pcap_file = sys.argv[1]
cap = pyshark.FileCapture(pcap_file, keep_packets=False)

csv_file = pcap_file.replace(".pcap", ".csv")

with open(csv_file, mode='w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow([
        "Timestamp", "Source", "Destination", "Protocol", "Length",
        "Src Port", "Dst Port", "TCP Flags", "TTL", "IP Header Length",
        "Total IP Length", "Window Size", "ICMP Type", "ICMP Code"
    ])

    for pkt in cap:
        try:
            timestamp = datetime.fromtimestamp(float(pkt.sniff_timestamp)).strftime("%Y-%m-%d %H:%M:%S")
            src = pkt.ip.src
            dst = pkt.ip.dst
            proto = pkt.transport_layer or pkt.highest_layer
            length = pkt.length

            # Defaults
            src_port = dst_port = flags = ttl = ip_hlen = ip_len = win_size = icmp_type = icmp_code = ""

            if "IP" in pkt:
                ttl = pkt.ip.ttl
                ip_len = pkt.ip.len
                ip_hlen = pkt.ip.hdr_len

            if "TCP" in pkt:
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
                flags = pkt.tcp.flags
                win_size = pkt.tcp.window_size

            elif "UDP" in pkt:
                src_port = pkt.udp.srcport
                dst_port = pkt.udp.dstport

            elif "ICMP" in pkt:
                icmp_type = pkt.icmp.type
                icmp_code = pkt.icmp.code

            writer.writerow([
                timestamp, src, dst, proto, length,
                src_port, dst_port, flags, ttl, ip_hlen,
                ip_len, win_size, icmp_type, icmp_code
            ])

        except AttributeError:
            continue  # skip packets with missing attributes