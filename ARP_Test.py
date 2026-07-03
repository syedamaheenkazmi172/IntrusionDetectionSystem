from scapy.all import ARP
from alert import alert

arp_table = {}

def check_arp(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        ip  = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        if ip in arp_table and arp_table[ip] != mac:
            alert('ARP_SPOOF', ip,
                  f'MAC changed from {arp_table[ip]} to {mac}',
                  severity=3)
        arp_table[ip] = mac

# Simulate a legit ARP reply first
pkt1 = ARP(op=2, psrc="10.0.2.2", hwsrc="52:55:0a:00:02:02")
check_arp(pkt1)
print("After legit reply:", arp_table)

# Simulate a spoofed reply — same IP, different MAC
pkt2 = ARP(op=2, psrc="10.0.2.2", hwsrc="DE:AD:BE:EF:00:11")
check_arp(pkt2)
print("After spoofed reply:", arp_table)
