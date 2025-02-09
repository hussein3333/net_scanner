# net_scanner
Network scanner using nmap

EDUCATION PURPOSES ONLY

Overview
</br>-This tool is a Python-based network scanner that utilizes python-nmap to perform Nmap scans and auto detects the local network if not provided. It supports different scanning modes: intense, stealthy, and quick scans.

Features
</br>-Automatic local network detection if no target is specified.

</br>-Multiple scan modes:

 </br> 1. Intense Scan: Quick and thorough but not stealthy.

</br>  2. Stealth Scan: Slower but avoids detection.

</br>  3. Quick Scan: Fast, but does not scan all ports.

</br>-Detection of live hosts, open ports, and running services.

</br>-OS and MAC address detection where applicable.

Usage
</br>-python network_scanner.py                # Scans your local network
</br>-python network_scanner.py -t 192.168.1.0/24  # Scans a specified network range

Scan Modes:
</br>-python network_scanner.py -i      # Intense scan (-sS --source-port 53 -p- -A -T4)
</br>-python network_scanner.py -s      # Stealth scan (-sS --source-port 53 -p- -sV)
</br>-python network_scanner.py -q      # Quick scan (-sT -n -T4)

Requirements

</br>-Python 3.x
</br>-Nmap (installed on your system)
</br>-Install required Python modules:
</br>-pip install python-nmap netifaces
