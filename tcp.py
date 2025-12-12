from scapy.all import sniff, TCP, IP
from collections import defaultdict

syn_counts = defaultdict(int)

def detect_syn(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        src = packet[IP].src
        syn_counts[src] += 1

        print(f"[SYN] {src} → Count = {syn_counts[src]}")

        if syn_counts[src] > 10:
            print(f"[ALERT] Possible SYN flood from {src}")

sniff(filter="tcp", prn=detect_syn, store=False)
# This script captures TCP packets on the network, counts SYN packets from each source IP, and raises an alert if a source exceeds 10 SYN packets.