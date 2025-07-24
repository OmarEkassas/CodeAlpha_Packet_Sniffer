from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
from datetime import datetime

def analyze_packet(packet):
    print("\n" + "="*50)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if IP in packet:
        ip_layer = packet[IP]
        print(f"🔹 Source IP: {ip_layer.src}")
        print(f"🔹 Destination IP: {ip_layer.dst}")
        print(f"🔹 Protocol: {ip_layer.proto}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP | Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP | Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")
        elif ICMP in packet:
            print("Protocol: ICMP")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload (truncated): {payload[:50]!r}")
    else:
        print("Non-IP packet captured (possibly ARP, etc.)")

# Start packet sniffing and store packets automatically
print("Starting packet capture for 10 seconds...\n")
captured_packets = sniff(prn=analyze_packet, store=True, timeout=10, iface="Wi-Fi")

# Save packets to a pcap file
pcap_file = "captured_traffic.pcap"
wrpcap(pcap_file, captured_packets)

print(f"\nsSaved {len(captured_packets)} packets to '{pcap_file}'")
