# net_scanner
Network scanner using nmap

EDUCATION PURPOSES ONLY

Overview
-This tool is a Python-based network scanner that utilizes python-nmap to perform Nmap scans and netifaces to auto-detect your local network if a target network is not specified. It supports different scanning modes, including intense, stealthy, and quick scans.

Features
-Automatic local network detection if no target is specified.

-Multiple scan modes:

  1. Intense Scan: Quick and thorough but not stealthy.

  2. Stealth Scan: Slower but avoids detection.

  3. Quick Scan: Fast, but does not scan all ports.

-Detection of live hosts, open ports, and running services.

-OS and MAC address detection where applicable.

Usage
-python network_scanner.py                # Scans your local network
-python network_scanner.py -t 192.168.1.0/24  # Scans a specified network range

Scan Modes

python network_scanner.py -i      # Intense scan (-sS --source-port 53 -p- -A -T4)
python network_scanner.py -s      # Stealth scan (-sS --source-port 53 -p- -sV)
python network_scanner.py -q      # Quick scan (-sT -n -T4)

Requirements

Python 3.x

Nmap (installed on your system)

Install required Python modules:
-pip install python-nmap netifaces
