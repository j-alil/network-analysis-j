# Network Traffic Analysis & Python Tools

This project combines manual network analysis using Wireshark with custom Python scripts designed to capture, inspect, and interpret real network traffic.  
It provides both a **technical report** (DNS, ICMP, TCP, HTTP, TLS analysis) and several **Python-based tools** demonstrating how protocol-level information can be extracted programmatically.

---

## Project Contents

### **1. Wireshark Analysis Report**
A complete analysis of several core Internet protocols, including:
- DNS request/response inspection  
- ICMP ping analysis  
- TCP 3-way handshake  
- HTTP plaintext communication  
- TLS 1.3 encrypted traffic  

The report includes screenshots, explanations, and a synthesis of observations.

---

### **2. Python Scripts (Scapy)**

This repository contains three standalone Python tools that replicate and automate parts of the Wireshark analysis:

#### ** dns_sniffer.py**
Captures DNS queries in real time and prints the requested domain name and source IP.

#### ** icmp_analyzer.py**
Sends ICMP Echo Requests and computes RTT and TTL values, similar to the Wireshark ping analysis.

#### ** syn_detector.py**
Monitors TCP SYN packets and raises alerts in case of repeated requests (simple anomaly/SYN flood detection).

Each script is small, focused, and designed to be understandable and modifiable.

---
