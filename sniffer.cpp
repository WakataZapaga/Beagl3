#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>       // For IP header
#include <netinet/tcp.h>      // For TCP header
#include <netinet/udp.h>      // For UDP header
#include <netinet/if_ether.h> // For Ethernet header
// #include <netinet/ip_icmp.h>  For ICMP header
#include <arpa/inet.h>        // For inet_ntop
#include <iomanip>            // For put_time
#include <csignal>            // For signal handling
#include <unistd.h>           // For getopt
#include <chrono>             // For timer
#include <thread>             // For std::thread
#include <string>             // For std::string

using namespace std;

// Global variables
pcap_dumper_t* dumper = nullptr;
pcap_t* handle = nullptr;

// Signal to stop packet capture
void handle_signal(int signal) {
    if (handle != nullptr) {
        cout << "\nSignal received. Stopping capture...\n";
        pcap_breakloop(handle); // Safely break the capture loop
    }
}

// Timer function to stop capture after specified duration
void timer_thread(int seconds) {
    this_thread::sleep_for(chrono::seconds(seconds));
    cout << "\nTime limit reached. Stopping capture...\n";
    handle_signal(SIGINT);
}

// Print readable protocol name from protocol number
void print_protocol(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP: cout << "TCP"; break;
        case IPPROTO_UDP: cout << "UDP"; break;
        case IPPROTO_ICMP: cout << "ICMP"; break;
        default: cout << "Other(" << static_cast<int>(proto) << ")"; break;
    }
}

// Callback function for each captured packet
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    // Write packet to pcap file
    pcap_dump((u_char*)dumper, header, packet);

    // Parse Ethernet header
    const struct ether_header* eth_header = (struct ether_header*)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) return; // Ignore non-IP packets

    // Parse IP header
    const struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    uint16_t src_port = 0, dst_port = 0;

    // Determine transport layer protocol and extract ports
    const u_char* transport_header = packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4);
    if (ip_header->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcp = (struct tcphdr*)transport_header;
        src_port = ntohs(tcp->th_sport);
        dst_port = ntohs(tcp->th_dport);
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        const struct udphdr* udp = (struct udphdr*)transport_header;
        src_port = ntohs(udp->uh_sport);
        dst_port = ntohs(udp->uh_dport);
    }

    // Print packet information
    time_t pkt_time = header->ts.tv_sec;
    tm* timeinfo = localtime(&pkt_time);

    cout << "Time: " << put_time(timeinfo, "%Y-%m-%d %H:%M:%S")
         << " | Size: " << header->len << " bytes"
         << " | Protocol: ";
    print_protocol(ip_header->ip_p);
    cout << "\n";

    cout << "   " << src_ip << ":" << src_port << " -> "
         << dst_ip << ":" << dst_port << "\n";
    cout << "---------------------------------------------\n";
}

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    string filename;
    string iface = "";
    string bpf_filter = "";
    int duration = 0;

    // Parse command-line arguments: [-i <interface>] [-t <duration>] [-f <filter>]
    int opt;
    while ((opt = getopt(argc, argv, "i:t:f:")) != -1) {
        switch (opt) {
            case 'i': iface = optarg; break;
            case 't': duration = stoi(optarg); break;
            case 'f': bpf_filter = optarg; break;
            default:
                cerr << "Usage: " << argv[0] << " [-i <interface>] [-t <duration>] [-f <filter>]\n";
                return 1;
        }
    }

    // Handle Ctrl+C interrupt
    signal(SIGINT, handle_signal);

    // Find all available devices
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }

    // Use first interface if none is specified
    if (iface.empty()) {
        if (!alldevs) {
            cerr << "No devices found." << endl;
            return 1;
        }
        iface = alldevs->name;
    }

    cout << "Using device: " << iface << endl;

    // Open live capture on specified interface
    handle = pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Could not open device: " << errbuf << endl;
        return 1;
    }

    // Apply BPF filter if provided
    if (!bpf_filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, bpf_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
            pcap_setfilter(handle, &fp) == -1) {
            cerr << "Failed to apply filter: " << pcap_geterr(handle) << endl;
            pcap_close(handle);
            return 1;
        }
        pcap_freecode(&fp);
        cout << "Applied filter: " << bpf_filter << endl;
    }

    // Get filename from user
    cout << "Enter the name for output file: ";
    cin >> filename;
    filename += ".pcap";

    // Open output dump file
    dumper = pcap_dump_open(handle, filename.c_str());
    if (!dumper) {
        cerr << "Failed to open dump file: " << pcap_geterr(handle) << endl;
        pcap_close(handle);
        return 1;
    }

    cout << "Sniffing packets and writing to " << filename << "...\n";
    if (duration > 0) {
        cout << "Capture will stop after " << duration << " seconds.\n";
        thread(timer_thread, duration).detach(); // Start duration timer
    } else {
        cout << "Press Ctrl+C to stop.\n";
    }

    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, nullptr);

    // Cleanup
    cout << "Cleaning up...\n";
    pcap_dump_close(dumper);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    cout << "Capture complete and file safely written.\n";

    // Auto-convert pcap file using external script
    string command = "python3 convert.py " + filename;
    system(command.c_str());

    return 0;
}