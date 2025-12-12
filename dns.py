from scapy.all import sniff, DNS, DNSQR, IP

def handle_dns(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        domain = packet[DNSQR].qname.decode()
        src_ip = packet[IP].src
        print(f"[DNS Query] {src_ip} → {domain}")

sniff(filter="udp port 53", prn=handle_dns, store=False)
# This script captures DNS query packets on the network and prints the source IP address along with the queried domain name.