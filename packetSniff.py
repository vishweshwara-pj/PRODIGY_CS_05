from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = packet.proto

        if packet.haslayer(TCP):
            protocol_name = "TCP"
        elif packet.haslayer(UDP):
            protocol_name = "UDP"
        else:
            protocol_name = "Other"

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol_name}")

        if Raw in packet:
            print(f"Payload: {packet[Raw].load}")

        print("-" * 50)

def start_sniffer(interface=None):
    print(f"Starting packet capture on interface: {interface}")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    # Replace "Wi-Fi" or "Ethernet" with your correct interface from the list
    start_sniffer(interface="Wi-Fi")
