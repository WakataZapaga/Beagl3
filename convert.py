from scapy.all import *
import csv
import sys
from datetime import datetime

def extract_info(pkt):
    info = {
        "Timestamp": "",
        "MAC Src": "",
        "MAC Dst": "",
        "IP Version": "",
        "Protocol": "",
        "IP Src": "",
        "Src Port": "",
        "IP Dst": "",
        "Dst Port": "",
        "TTL": "",
        "IP Header Len": "",
        "TCP Flags": "",
        "Window Size": "",
        "ICMP Type": "",
        "ICMP Code": "",
        "Length": "",
    }

    info["Timestamp"] = datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S")
    info["Length"] = len(pkt)

    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        info["MAC Src"] = eth.src
        info["MAC Dst"] = eth.dst

    if pkt.haslayer(IP):
        ip = pkt[IP]
        info["IP Version"] = ip.version
        info["IP Src"] = ip.src
        info["IP Dst"] = ip.dst
        info["TTL"] = ip.ttl
        info["IP Header Len"] = ip.ihl * 4  # in bytes

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            info["Protocol"] = "TCP"
            info["Src Port"] = tcp.sport
            info["Dst Port"] = tcp.dport
            info["TCP Flags"] = tcp.sprintf("%TCP.flags%")
            info["Window Size"] = tcp.window

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            info["Protocol"] = "UDP"
            info["Src Port"] = udp.sport
            info["Dst Port"] = udp.dport

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            info["Protocol"] = "ICMP"
            info["ICMP Type"] = icmp.type
            info["ICMP Code"] = icmp.code

        else:
            info["Protocol"] = str(ip.proto)

    return info

def main():
    if len(sys.argv) != 2:
        print("Usage: python convert.py <file.pcap>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    csv_file = pcap_file.replace(".pcap", ".csv")

    packets = rdpcap(pcap_file)

    fieldnames = [
        "Timestamp", "MAC Src", "MAC Dst", "IP Version", "Protocol",
        "IP Src", "Src Port", "IP Dst", "Dst Port", "TTL",
        "IP Header Len", "TCP Flags", "Window Size",
        "ICMP Type", "ICMP Code", "Length"
    ]

    with open(csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for pkt in packets:
            try:
                info = extract_info(pkt)
                writer.writerow(info)
            except Exception as e:
                print(f"Skipping packet due to error: {e}")

    print(f"[+] CSV file written: {csv_file}")

if __name__ == "__main__":
    main()