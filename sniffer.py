"""
Copilot-Assisted Packet Sniffer: Seeing the Network (Ethically)

This tool captures network packets from authorized interfaces/files only,
decodes common protocols, and redacts sensitive information.
"""

import argparse
import sys
import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, Ether
from redaction import redact_ip, redact_sensitive, mask_payload

# Configure logging
log_filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    filename=log_filename,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
console = logging.StreamHandler(sys.stdout)
console.setLevel(logging.INFO)
logging.getLogger('').addHandler(console)

# Allowed interfaces (whitelist)
ALLOWED_INTERFACES = ["lo", "eth0", "eth1", "wlan0", "wlan1", "docker0", "veth"]
PACKET_COUNT = 0


def packet_callback(packet):
    """Process each captured packet."""
    global PACKET_COUNT
    PACKET_COUNT += 1
    
    output = []
    output.append(f"\n--- Packet #{PACKET_COUNT} ---")
    
    try:
        # Layer 2: Ethernet
        if Ether in packet:
            eth = packet[Ether]
            output.append(f"[Ethernet] Src: {eth.src} | Dst: {eth.dst}")
        
        # Layer 3: IP
        if IP in packet:
            ip = packet[IP]
            ip_src = redact_ip(ip.src)
            ip_dst = redact_ip(ip.dst)
            output.append(f"[IP] {ip_src} → {ip_dst} | Proto: {ip.proto} | TTL: {ip.ttl}")
        
        # Layer 4: TCP/UDP
        if TCP in packet:
            tcp = packet[TCP]
            flags = tcp.flags if hasattr(tcp, 'flags') else 0
            output.append(f"[TCP] Port {tcp.sport} → {tcp.dport} | Flags: {flags} | Seq: {tcp.seq} | Ack: {tcp.ack}")
        
        if UDP in packet:
            udp = packet[UDP]
            output.append(f"[UDP] Port {udp.sport} → {udp.dport} | Length: {udp.len}")
        
        # DNS queries
        if DNS in packet and DNSQR in packet[DNS]:
            dns_qr = packet[DNS][DNSQR]
            domain = dns_qr.qname.decode('utf-8', errors='ignore').rstrip('.')
            output.append(f"[DNS] Query: {redact_sensitive(domain)}")
        
        # HTTP and Raw Payload
        if Raw in packet:
            payload = packet[Raw].load
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                # Check for HTTP request line
                lines = payload_str.split('\r\n')[:5]  # First 5 lines
                for line in lines:
                    if 'GET' in line or 'POST' in line or 'Host:' in line:
                        redacted_line = redact_sensitive(line)
                        output.append(f"[HTTP] {redacted_line}")
            except Exception:
                pass
        
        log_entry = "\n".join(output)
        logging.info(log_entry)
        print(log_entry)
    
    except Exception as e:
        logging.error(f"Error processing packet: {str(e)}")


def validate_interface(iface):
    """Validate that the interface is in the allowlist."""
    for allowed in ALLOWED_INTERFACES:
        if iface.startswith(allowed):
            return True
    return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Copilot-Assisted Packet Sniffer (Ethical) - Capture authorized lab traffic only",
        epilog="Example: python sniffer.py --iface lo --count 25 --filter 'tcp port 80'"
    )
    parser.add_argument(
        "--iface",
        help="Network interface to sniff on (default: lo)",
        default="lo"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=25,
        help="Number of packets to capture (default: 25)"
    )
    parser.add_argument(
        "--filter",
        help="BPF filter (e.g., 'tcp', 'udp port 53', 'tcp port 80')",
        default=""
    )
    parser.add_argument(
        "--pcap",
        help="Read from .pcap file instead of live capture (safe alternative)",
        default=None
    )
    
    args = parser.parse_args()
    
    logging.info("="*60)
    logging.info("Copilot-Assisted Packet Sniffer Started")
    logging.info("="*60)
    
    # Mode 1: Read from PCAP file (safe, no privilege issues)
    if args.pcap:
        logging.info(f"Reading from file: {args.pcap}")
        try:
            sniff(
                offline=args.pcap,
                prn=packet_callback,
                count=args.count,
                filter=args.filter,
                store=False
            )
        except FileNotFoundError:
            logging.error(f"PCAP file not found: {args.pcap}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error reading PCAP: {str(e)}")
            sys.exit(1)
    
    # Mode 2: Live capture from interface (with allowlist validation)
    else:
        if not validate_interface(args.iface):
            logging.error(f"Interface '{args.iface}' not in allowlist: {ALLOWED_INTERFACES}")
            logging.error("You may only sniff on loopback or authorized lab interfaces.")
            sys.exit(1)
        
        logging.info(f"Sniffing on interface: {args.iface}")
        logging.info(f"Capture limit: {args.count} packets")
        logging.info(f"Filter: {args.filter if args.filter else '(none)'}")
        logging.info("All sensitive data will be redacted.")
        logging.info("Press Ctrl+C to stop.\n")
        
        try:
            sniff(
                iface=args.iface,
                prn=packet_callback,
                count=args.count,
                filter=args.filter,
                store=False
            )
        except PermissionError:
            logging.error("Permission denied. Run with sudo/administrator privileges.")
            logging.info("Alternative: Use --pcap to read from a pre-captured file.")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error during capture: {str(e)}")
            sys.exit(1)
    
    logging.info("="*60)
    logging.info(f"Capture complete. Total packets: {PACKET_COUNT}")
    logging.info(f"Log saved to: {log_filename}")
    logging.info("="*60)


if __name__ == "__main__":
    main()
