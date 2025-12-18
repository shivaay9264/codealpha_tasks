
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from datetime import datetime


def packet_callback(packet):

    # Check if packet has IP layer
    if packet.haslayer(IP):

        print("\n" + "=" * 60)

        # Time formatting
        capture_time = datetime.fromtimestamp(packet.time)
        print(f"Time       : {capture_time}")

        # MAC Address info (Layer 2)
        if packet.haslayer(Ether):
            print(f"MAC        : {packet[Ether].src}  ->  {packet[Ether].dst}")

        # IP Address info
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"IP         : {src_ip}  ->  {dst_ip}")

        # Protocol Identification
        if packet.haslayer(TCP):
            proto_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Protocol   : TCP")
            print(f"Ports      : {src_port}  ->  {dst_port}")

        elif packet.haslayer(UDP):
            proto_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"Protocol   : UDP")
            print(f"Ports      : {src_port}  ->  {dst_port}")

        elif packet.haslayer(ICMP):
            proto_name = "ICMP"
            print(f"Protocol   : ICMP")

        else:
            proto_name = "Other"
            print(f"Protocol   : Other")

        # Payload extraction
        if packet.haslayer("Raw"):
            try:
                payload = packet["Raw"].load.decode("utf-8", errors="ignore")
                print("Payload    :")
                print(payload[:150])  # Limit output
            except Exception:
                print("Payload    : [Non-readable data]")
        else:
            print("Payload    : [No application data]")


def start_sniffing(interface=None, count=0):
    print("[*] Network Packet Sniffer Started")
    print(f"[*] Interface : {interface if interface else 'Default'}")
    print("[*] Press Ctrl + C to stop\n")

    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            count=count,
            store=0
        )
    except KeyboardInterrupt:
        print("\n[*] Packet capture stopped by user.")


if __name__ == "__main__":
    # Run with count=0 for infinite capture
    start_sniffing(count=0)
