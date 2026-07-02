import socket, struct, time
from collections import defaultdict
from alert import alert

THRESHOLD = 20
WINDOW = 5
ICMP_THRESHOLD = 50
ICMP_WINDOW = 1
SSH_THRESHOLD = 10
SSH_WINDOW = 60

syn_tracker = defaultdict(list)
icmp_tracker = defaultdict(list)
ssh_tracker = defaultdict(list)


s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

print('IDS running...')

while True:
	raw_data, _ = s.recvfrom(65535)
	ip_header = raw_data[14:34]
	iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
	
	if iph[6] == 6:
		tcp_header = raw_data[34:54]
		tcph = struct.unpack('!HHLLBBHHH', tcp_header)
		flags = tcph[5]
		src_ip = socket.inet_ntoa(iph[8])
		syn = (flags & 0x02) != 0
		ack = (flags & 0x10) != 0
	
		if syn and not ack:
			now =  time.time()
			syn_tracker[src_ip].append(now)
			syn_tracker[src_ip] = [
				t for t in syn_tracker[src_ip]
				if now - t < WINDOW
			]
			if len(syn_tracker[src_ip]) > THRESHOLD:
				alert('PORT_SCAN', src_ip,
					f'{len(syn_tracker[src_ip])} SYNs in {WINDOW}s',
					severity = 2)

		d_port = tcph[1]
		if syn and not ack and d_port == 22:
			now = time.time()
			ssh_tracker[src_ip].append(now)
			ssh_tracker[src_ip] = [
				t for t in ssh_tracker[src_ip]
				if now - t < SSH_WINDOW
			]
			if len(ssh_tracker[src_ip]) > SSH_THRESHOLD:
				alert('SSH_BRUTE', src_ip,
					f'{len(ssh_tracker[src_ip])} SSH attempts in {SSH_WINDOW}s',
					severity = 2) 


	elif iph[6] == 1:
		icmp_header = raw_data[34:38]
		icmph = struct.unpack('!BBH', icmp_header)
		icmp_type = icmph[0]
		src_ip = socket.inet_ntoa(iph[8])
		
		if icmp_type == 8:
			now = time.time()
			icmp_tracker[src_ip].append(now)
			icmp_tracker[src_ip] = [
				t for t in icmp_tracker[src_ip]
				if now - t < ICMP_WINDOW
			]
			if len(icmp_tracker[src_ip]) > ICMP_THRESHOLD:
				alert('ICMP_FLOOD', src_ip,
					f'{len(icmp_tracker[src_ip])} pings in {ICMP_WINDOW}s',
                                        severity=3)
