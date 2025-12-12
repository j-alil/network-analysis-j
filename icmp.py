from scapy.all import *
import time

def ping_host(host):
    packet = IP(dst=host)/ICMP()
    start = time.time()
    reply = sr1(packet, timeout=2, verbose=0)
    end = time.time()

    if reply:
        rtt = (end - start) * 1000
        print(f"Reply from {host} — TTL={reply.ttl}, RTT={rtt:.2f} ms")
    else:
        print("No reply received.")

ping_host("8.8.8.8")
# This script sends an ICMP echo request (ping) to a specified host and prints the reply details including TTL and RTT.