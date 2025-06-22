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

        # Protocol type one-hot
        "protocol_type_tcp": 0,
        "protocol_type_udp": 0,
        "protocol_type_icmp": 0,

        # TCP flag indicators
        "flag_S0": 0,
        "flag_SF": 0,
        "flag_REJ": 0,
        "flag_RSTO": 0,
        "flag_RSTR": 0,

        # Service type indicators (based on dst port)
        "service_http": 0,
        "service_domain": 0,
        "service_ftp_data": 0,
        "service_ssh": 0,
        "service_smtp": 0,
        "service_private": 0,
        "service_other": 0
    }

    try:
        info["Timestamp"] = datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S")
    except:
        info["Timestamp"] = ""

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
        info["IP Header Len"] = ip.ihl * 4

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            info["Protocol"] = "TCP"
            info["Src Port"] = tcp.sport
            info["Dst Port"] = tcp.dport
            info["TCP Flags"] = tcp.sprintf("%TCP.flags%")
            info["Window Size"] = tcp.window

            info["protocol_type_tcp"] = 1

            flags = tcp.flags

            # Flag logic
            if flags == 0x02:  # SYN only
                info["flag_S0"] = 1
            elif flags == 0x12:  # SYN + ACK
                info["flag_SF"] = 1
            elif flags == 0x04:  # RST
                info["flag_REJ"] = 1
            elif flags == 0x14:  # RST + ACK
                info["flag_RSTR"] = 1
            elif flags == 0x05:  # FIN + RST (unusual)
                info["flag_RSTO"] = 1

            # Service logic based on destination port
            port = tcp.dport
            if port == 80:
                info["service_http"] = 1
            elif port in [20, 21]:
                info["service_ftp_data"] = 1
            elif port == 22:
                info["service_ssh"] = 1
            elif port == 25:
                info["service_smtp"] = 1
            elif port == 53:
                info["service_domain"] = 1
            elif 49152 <= port <= 65535:
                info["service_private"] = 1
            else:
                info["service_other"] = 1

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            info["Protocol"] = "UDP"
            info["Src Port"] = udp.sport
            info["Dst Port"] = udp.dport

            info["protocol_type_udp"] = 1

            port = udp.dport
            if port == 53:
                info["service_domain"] = 1
            elif 49152 <= port <= 65535:
                info["service_private"] = 1
            else:
                info["service_other"] = 1

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            info["Protocol"] = "ICMP"
            info["ICMP Type"] = icmp.type
            info["ICMP Code"] = icmp.code

            info["protocol_type_icmp"] = 1

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
        "ICMP Type", "ICMP Code", "Length",
        "protocol_type_tcp", "protocol_type_udp", "protocol_type_icmp",
        "flag_S0", "flag_SF", "flag_REJ", "flag_RSTO", "flag_RSTR",
        "service_http", "service_domain", "service_ftp_data", "service_ssh",
        "service_smtp", "service_private", "service_other"
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