#combining all parts here in one single file
import socket
import struct 
import time
import signal
import sys
from collections import defaultdict
import logging
import json
from alert import alert

# raw socket needs root
try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except PermissionError:
        print("Error: raw sockets need root privileges. Run this with sudo.")
        sys.exit(1)

# handle ctrl+c and systemctl stop cleanly
def shutdown(signum, frame):
        print("\nShutting down IDS.")
        s.close()
        sys.exit(0)

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

#for syn_packets to detect scans
syn_ports=defaultdict(set)          # distinct destination ports hit per source ip
port_threshold=15                   # distinct ports in the window = scan
syn_window=10 #seconds

# for icmp flood detection
icmp_tracker=defaultdict(list)
icmp_threshold=50
icmp_window=1

# for ssh brute force detection
ssh_tracker=defaultdict(list)
ssh_threshold=10
ssh_window=60

#arp table
arp_table={}

#detecting OS logic
os_fingerprint_cache={} #so program does not check os every time a new packet comes

def detect_os(ttl, window):
        if ttl<=64:
                base_ttl=64
        elif ttl<=128:
                base_ttl=128
        else:
                base_ttl=255

        if base_ttl==64:
                if window in (5840,14600,29200,5720):
                        return "Linux (likely)"
                elif window in (65535,65280):
                        return "macOS/BSD (likely)"
                return "Linux/Unix (likely)"
        elif base_ttl==128:
                return "Windows (likely)"
        else:
                return "Network device / legacy Unix (likely)"


print("IDS Running..")

while True:
        raw_data, addr= s.recvfrom(65535) #capturing packets

        # extracting ethernet header
        ethernet=raw_data[:14]
        eth_header=struct.unpack("!6s6sH", ethernet)
        ethertype=eth_header[2]

        if ethertype==0x0800:

                #skipping ethernet header that are the first 14 bytes
                ip=raw_data[14:34]

                try:
                        ip_header=struct.unpack("!BBHHHBBH4s4s",ip)
                except struct.error:
                        continue  # skip malformed ip header instead of crashing

                version=ip_header[0] >> 4
                src=ip_header[8]
                dst=ip_header[9]
                protocol=ip_header[6]
                ttl=ip_header[5]

                src_ip=socket.inet_ntoa(src)
                dst_ip=socket.inet_ntoa(dst)

                if protocol==6:
                        try:
                                tcp=raw_data[34:54]
                                tcp_header=struct.unpack('!HHLLBBHHH',tcp)
                        except struct.error:
                                continue  # truncated/weird packet, skip instead of crashing

                        src_port=tcp_header[0]
                        dst_port=tcp_header[1]
                        flags=tcp_header[5]

                        syn=(flags & 0x02) !=0
                        ack=(flags & 0x10) !=0
                        fin=(flags & 0x01) !=0
                        rst=(flags & 0x04) !=0

                        #checking port scanning logic, using distinct ports hit
                        if syn and not ack: #indicates probing
                                if src_ip not in os_fingerprint_cache: #added this for guessing os
                                        os_fingerprint_cache[src_ip]=detect_os(ttl, tcp_header[6])

                                syn_ports[src_ip].add(dst_port)

                                if len(syn_ports[src_ip])>port_threshold:
                                        alert('PORT_SCAN', src_ip,
                                              f'{len(syn_ports[src_ip])} distinct ports scanned (last hit: {dst_ip}:{dst_port}) [suspected OS: {os_fingerprint_cache[src_ip]}]',
                                              severity=2)

                        # for brute force detection
                        if syn and not ack and dst_port==22:
                                now=time.time()
                                ssh_tracker[src_ip].append(now)
                                ssh_tracker[src_ip]=[
                                        t for t in ssh_tracker[src_ip]
                                        if now-t<ssh_window
                                ]
                                if len(ssh_tracker[src_ip]) >ssh_threshold:
                                        alert('SSH_BRUTE', src_ip,
                                              f'{len(ssh_tracker[src_ip])} SSH attempts to {dst_ip} in {ssh_window}s [suspected OS: {os_fingerprint_cache[src_ip]}]',
                                              severity=2)

                elif protocol==1:
                        icmp=raw_data[34:42]
                        try:
                                icmp_header=struct.unpack('!BBHHH',icmp)
                        except struct.error:
                                continue

                        icmp_type=icmp_header[0]

                        if icmp_type==8: #indicates echo request
                                now=time.time()
                                icmp_tracker[src_ip].append(now)

                                icmp_tracker[src_ip]=[
                                        t for t in icmp_tracker[src_ip]
                                        if now-t<icmp_window
                                ]

                                if len(icmp_tracker[src_ip])>icmp_threshold:
                                        alert('ICMP_FLOOD', src_ip, f'{len(icmp_tracker[src_ip])} pings in {icmp_window}s',severity=3)

        elif ethertype==0x0806:
                # skipping ethernet header and extracting arp packet
                arp=raw_data[14:42]
                try:
                        arp_header=struct.unpack("!HHBBH6s4s6s4s",arp)
                except struct.error:
                        continue
                opcode=arp_header[4]
                sender_mac=":".join(f"{b:02x}" for b in arp_header[5])
                sender_ip=socket.inet_ntoa(arp_header[6])
                # we only check arp replies because they can poison arp caches
                if opcode==2:
                        if sender_ip in arp_table:
                                if arp_table[sender_ip]!=sender_mac:
                                        alert('ARP_SPOOF', sender_ip,
                                                f'MAC changed from {arp_table[sender_ip]} to {sender_mac}', severity=3
                                        )
                        arp_table[sender_ip]=sender_mac
