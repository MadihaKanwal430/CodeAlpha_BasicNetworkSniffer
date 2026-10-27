# CodeAlpha_BasicNetworkSniffer
# Basic Network Sniffer

**CodeAlpha Cyber Security Internship – Task 1**

## Project Description
A Python-based network packet sniffer that captures and analyzes network traffic using the Scapy library. It displays packet details and saves captured information in a CSV file.

## Features
- Real-time network packet capturing
- TCP, UDP, and ICMP protocol detection
- Source and destination IP addresses
- Source and destination port numbers
- Packet size and timestamp
- Payload inspection in hexadecimal format
- CSV file export

## Technologies Used
- Python
- Scapy
- Npcap (Windows)
- PyCharm

## Installation

Install the required library:

```bash
pip install scapy
```

Install Npcap on Windows from https://npcap.com/.

## How to Run

```bash
python network_sniffer.py
```

Run with administrator privileges if required.

The program captures up to 20 packets or runs for 30 seconds.

## Project Structure

```text
CodeAlpha_BasicNetworkSniffer/
├── network_sniffer.py
├── requirements.txt
├── README.md
└── screenshots/
    └── output.png
```

## Learning Outcomes
Gained practical experience in network packet capturing, protocol analysis, IP addressing, and network traffic monitoring using Python.

## Disclaimer
This project is developed for educational purposes and authorized network monitoring only.

---
**Internship:** CodeAlpha Cyber Security  
**Task:** Basic Network Sniffer
