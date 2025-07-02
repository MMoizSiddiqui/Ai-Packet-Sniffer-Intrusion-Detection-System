from scapy.all import IP, TCP, send
import random

target_ip = "127.0.0.1"  # Change to your sniffer's IP if needed
target_port = 80

for i in range(20):
    src_port = random.randint(1024, 65535)
    pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="S")
    send(pkt, verbose=False)

print("Malicious SYN packets sent!") 