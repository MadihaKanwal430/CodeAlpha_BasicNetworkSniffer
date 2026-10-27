
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw
from datetime import datetime
import csv

# ==========================================
# BASIC NETWORK PACKET SNIFFER
# ==========================================

CSV_FILE = "captured_packets.csv"
MAX_PACKETS =50
CAPTURE_TIMEOUT = 120

packet_count = 0


# Create CSV file
def create_csv():
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Timestamp",
            "Source IP",
            "Destination IP",
            "Protocol",
            "Source Port",
            "Destination Port",
            "Packet Length",
            "Payload"
        ])


# Identify network protocol
def get_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(IPv6):
        return "IPv6"
    else:
        return "OTHER"


# Process captured packets
def analyze_packet(packet):
    global packet_count

    if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
        return

    packet_count += 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Extract IP addresses
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
    else:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    protocol = get_protocol(packet)

    source_port = "N/A"
    destination_port = "N/A"

    # Extract ports
    if packet.haslayer(TCP):
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    packet_length = len(packet)

    # Extract payload
    payload = "No Payload"

    if packet.haslayer(Raw):
        raw_data = bytes(packet[Raw].load)
        payload = raw_data[:100].hex()

    # Display packet information
    print("\n" + "=" * 55)
    print(f"Packet Number  : {packet_count}")
    print(f"Timestamp      : {timestamp}")
    print(f"Source IP      : {source_ip}")
    print(f"Destination IP : {destination_ip}")
    print(f"Protocol       : {protocol}")
    print(f"Source Port    : {source_port}")
    print(f"Destination Port: {destination_port}")
    print(f"Packet Length  : {packet_length} bytes")
    print(f"Payload (Hex)  : {payload}")
    print("=" * 55)

    # Save packet information in CSV
    with open(CSV_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_length,
            payload
        ])


# Main function
def main():
    print("=" * 55)
    print("       BASIC NETWORK PACKET SNIFFER")
    print("       CodeAlpha Cyber Security Internship")
    print("=" * 55)

    create_csv()

    print("\nStarting packet capture...")
    print(f"Maximum Packets: {MAX_PACKETS}")
    print(f"Capture Timeout: {CAPTURE_TIMEOUT} seconds")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            prn=analyze_packet,
            store=False,
            count=MAX_PACKETS,
            timeout=CAPTURE_TIMEOUT
        )

    except KeyboardInterrupt:
        print("\nPacket capturing stopped by user.")

    except PermissionError:
        print("\nError: Run PyCharm as Administrator.")

    except Exception as e:
        print(f"\nError: {e}")

    finally:
        print("\n" + "=" * 55)
        print("PACKET CAPTURE SUMMARY")
        print(f"Total IP Packets Captured: {packet_count}")
        print(f"CSV File: {CSV_FILE}")
        print("=" * 55)


if __name__ == "__main__":
    main()
