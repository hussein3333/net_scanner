"""
Network Scanner Tool
--------------------

This tool uses python-nmap to perform an Nmap scan and netifaces to auto-detect
your local network if a target network is not specified.

Usage:
    python network_scanner.py                # Scans your local network
    python network_scanner.py -t 192.168.1.0/24  # Scans the specified network range

Requirements:
    - Python 3.x
    - nmap (installed on your system)
    - python-nmap: pip install python-nmap
    - netifaces: pip install netifaces
"""

import argparse
import ipaddress
import sys
import nmap
import netifaces


def get_local_network():
    """
    Automatically determine the local network (e.g. 192.168.1.0/24)
    based on the default gateway interface.
    """
    try:
        gateways = netifaces.gateways() # Get list of network gateways on the system
        
        # Get the default gateway for IPv4
        default_gateway = gateways['default'][netifaces.AF_INET]
        interface = default_gateway[1]
        iface_data = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        ip_addr = iface_data['addr']
        netmask = iface_data['netmask']
        
        network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
        return str(network) # Return the network range as string
        
    except Exception as e:
        print(f"[ERROR] Could not determine local network: {e}")
        sys.exit(1)


def run_nmap_scan(target, options):
    scanner = nmap.PortScanner()
    print(f"[INFO] Starting scan on {target} ...")
    try:
        scanner.scan(hosts=target, arguments=options) # Use options provided to start scan
    except Exception as e:
        print(f"[ERROR] Nmap scan failed: {e}")
        sys.exit(1)
    return scanner


def print_scan_results(scanner):
    """
    Iterate over the scan results and print details for each host.
    """
    for host in scanner.all_hosts():
        print("=" * 60)
        hostname = scanner[host].hostname() or "N/A"
        state = scanner[host].state()
        print(f"Host: {host} ({hostname})")
        print(f"State: {state}")

        # Print MAC address and vendor info if available
        addresses = scanner[host].get("addresses", {})
        if "mac" in addresses:
            mac = addresses["mac"]
            print(f"MAC Address: {mac}")
            vendor = scanner[host].get("vendor", {}).get(mac, "Unknown")
            print(f"Vendor: {vendor}")

        # Print OS detection info if available
        if "osmatch" in scanner[host]:
            os_matches = scanner[host]["osmatch"]
            if os_matches:
                print("OS Matches:")
                for osmatch in os_matches:
                    name = osmatch.get("name", "Unknown")
                    accuracy = osmatch.get("accuracy", "N/A")
                    print(f"  - {name} (Accuracy: {accuracy}%)")
            else:
                print("OS detection: No matches found.")

        # Print open TCP ports and service info
        if "tcp" in scanner[host]:
            print("Open TCP Ports:")
            for port in sorted(scanner[host]["tcp"].keys()):
                port_data = scanner[host]["tcp"][port]
                state = port_data.get("state", "unknown")
                service = port_data.get("name", "unknown")
                product = port_data.get("product", "")
                version = port_data.get("version", "")
                extrainfo = port_data.get("extrainfo", "")
                print(f"\tPort {port}: {state} ({service} {product} {version} {extrainfo})")

        # Optionally, you could include UDP scan details here if needed but UDP scans take much longer since it doesn't acknowledge received packets
        print("=" * 60)
        print("")


def main():
    # You can adjust the Nmap arguments as needed. 
    # Examples:
    
    # Use port 53 to bypass some firewall configurations --source-port 53
    # T1-T5 to facilitate scan speed on the faster side (e.g., -T4)
    # Faster and stealthier scan using TCP SYN scan (Doesn't require a full 3 way handshake) -sS  MIGHT REQUIRE admin perms
    # Aggresive scan (OS detection, default scripts, version scan) -A
    # Scan all ports using -p-
    # -sV service version scan
    
    
    parser = argparse.ArgumentParser(
        description="A network scanning tool using Nmap and netifaces."
    )
    parser.add_argument(
        "-t",
        "--target",
        help="Target network (e.g., 192.168.1.0/24). If not provided, uses the local network.",
        default=None,
    )
    parser.add_argument(
        "-i",
        "--intense",
        action="store_true",
        help="Intense scan (Quick and thorough, but not stealthy): -sS --source-port 53 -p- -A -T4"
    )
    parser.add_argument(
        "-s",
        "--stealth",
        action="store_true",
        help="Slow, but stealthy: -sS --source-port 53 -p- -sV"
    )
    parser.add_argument(
        "-q",
        "--quick",
        action="store_true",
        help="Quick, but not stealthy (Doesn't scan all ports): -sT -n -T4",
    )
    args = parser.parse_args()
    
    # Determine target network: use the provided target or auto-detect local network.
    target = args.target or get_local_network()
    if not args.target:
        print(f"[INFO] No target specified. Using local network: {target}")
    if args.intense:
        scanner = run_nmap_scan(target, '-sS --source-port 53 -p- -A -T4')
    elif args.stealth:
        scanner = run_nmap_scan(target, '-sS --source-port 53 -p- -sV')
    # Run the Nmap scan
    else:
        scanner = run_nmap_scan(target, '-sT -n -T4 -oA {adsadsasd}')
    # Print the results in a human-friendly format.
    print_scan_results(scanner)


if __name__ == "__main__":
    main()
