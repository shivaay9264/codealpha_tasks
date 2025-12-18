Network Packet Sniffer

A lightweight network packet sniffer tool built using Python and the scapy library. This script captures network traffic in real-time and analyzes headers to extract source/destination IPs, MAC addresses, protocols (TCP/UDP/ICMP), and payload data.
🚀 Features

    Real-time Monitoring: Captures packets live from the network interface.

    Layer 2 Analysis: Extracts Source and Destination MAC addresses.

    Layer 3 Analysis: Extracts Source and Destination IP addresses.

    Protocol Detection: Identifies TCP, UDP, and ICMP packets.

    Port Scanning: Displays Source and Destination ports for TCP/UDP.

    Payload Extraction: Attempts to decode and display the packet payload (data) in UTF-8 format.

📋 Prerequisites

Before running this script, ensure you have the following installed:

    Python 3.x

    Scapy Library

    Npcap (For Windows users only - usually installed with Wireshark)

    Root/Administrator Privileges (Required to access network interfaces)

🛠️ Installation

    Clone or Download this repository/script.

    Install Scapy using pip:
    Bash

    pip install scapy

    (Windows Only): Download and install Npcap (Select "Install Npcap in WinPcap API-compatible Mode" during installation).

💻 Usage

To sniff network traffic, you must run the script with administrative privileges.
Linux / macOS

Open your terminal and run:
Bash

sudo python3 sniffer.py

Windows

Open Command Prompt or PowerShell as Administrator and run:
DOS

python sniffer.py

(Note: Replace sniffer.py with the actual name of your python file)
🔍 Output Example

When the script is running, you will see output similar to this:
Plaintext

[*] Network Packet Sniffer Started
[*] Interface : Default
[*] Press Ctrl + C to stop

============================================================
Time       : 2023-10-27 14:30:05.123456
MAC        : 00:11:22:33:44:55  ->  AA:BB:CC:DD:EE:FF
IP         : 192.168.1.5  ->  142.250.190.46
Protocol   : TCP
Ports      : 54321  ->  443
Payload    : [Non-readable data]

============================================================
Time       : 2023-10-27 14:30:06.987654
MAC        : AA:BB:CC:DD:EE:FF  ->  00:11:22:33:44:55
IP         : 192.168.1.1  ->  192.168.1.5
Protocol   : UDP
Ports      : 53  ->  61234
Payload    : [No application data]

⚠️ Disclaimer & Ethical Use

Educational Purpose Only: This tool is intended for educational purposes and for testing networks you own or have explicit permission to audit.

    Do not use this tool on unauthorized networks.

    Unauthorized interception of data is illegal in many jurisdictions.

    The author is not responsible for any misuse of this code.

🤝 Contributing

Feel free to fork this project and submit pull requests for improvements!
📜 License

This project is open-source. Feel free to use and modify it.
