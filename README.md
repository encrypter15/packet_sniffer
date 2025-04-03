
### README.md for packet_sniffer.py

```markdown
# Packet Sniffer

## Overview
The Packet Sniffer is a Python tool that captures network packets on a specified interface using the `scapy` library. It logs packet summaries and provides a simple way to monitor network traffic.

## Author
Rick Hayes

## License
MIT

## Version
2.73

## Requirements
- Python 3.x
- `scapy` library (`pip install scapy`)
- Root privileges (e.g., run with `sudo`)
- Network interface access

## Usage
Run the script with root privileges using the following arguments:

```bash
sudo python3 packet_sniffer.py --interface <INTERFACE> [--count <COUNT>] [--config <CONFIG_FILE>]Arguments--interface (required): Network interface to sniff (e.g., eth0, wlan0).--count (optional): Number of packets to capture (default: 10).--config (optional): Path to a JSON configuration file (defaults to config.json).Examplesudo python3 packet_sniffer.py --interface eth0 --count 20ConfigurationThe tool supports a JSON configuration file to specify a packet filter. Example config.json:{
    "filter": "ip"
}filter: A Scapy filter string to limit captured packets (default: "ip"). Examples: "tcp", "udp", "arp".OutputConsole: Prints a summary of each captured packet.Log file: Logs packet summaries to packet_sniffer.log with timestamps.Error HandlingPermission Errors: Exits with an error if not run with root privileges.Invalid Count: Exits if the count is not a positive integer.Sniffing Errors: Logs and reports issues like invalid interfaces.NotesRequires root privileges due to raw socket access.Use responsibly on networks you own or have permission to monitor, as packet sniffing may be regulated by law.The default filter captures only IP packets; adjust in config for broader or narrower scope.
