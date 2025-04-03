#!/usr/bin/env python3
# Packet Sniffer
# Author: Rick Hayes
# License: MIT
# Version: 2.73
# README: Requires scapy, root privileges. Sniffs packets and logs summaries.

import scapy.all as scapy
import argparse
import logging
import json
from typing import Optional

def setup_logging():
    """Configure logging to file."""
    logging.basicConfig(filename='packet_sniffer.log', level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(config_file: str) -> dict:
    """Load configuration from JSON file."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Config loading failed: {e}")
        return {"filter": "ip"}

def packet_callback(packet):
    """Callback to process each packet."""
    summary = packet.summary()
    logging.info(f"Captured packet: {summary}")
    print(summary)

def main():
    """Main function to parse args and sniff packets."""
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("--interface", required=True, help="Network interface (e.g., eth0)")
    parser.add_argument("--count", type=int, default=10, help="Number of packets to capture")
    parser.add_argument("--config", default="config.json", help="Config file path")
    args = parser.parse_args()

    setup_logging()
    config = load_config(args.config)

    if args.count <= 0:
        logging.error("Count must be positive")
        print("Error: Count must be a positive integer")
        return

    logging.info(f"Starting packet capture on {args.interface} for {args.count} packets")
    try:
        scapy.sniff(iface=args.interface, count=args.count, filter=config["filter"],
                    prn=packet_callback)
    except PermissionError as e:
        logging.error(f"Permission denied: {e}")
        print("Error: This tool requires root privileges")
    except Exception as e:
        logging.error(f"Sniffing error: {e}")
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
