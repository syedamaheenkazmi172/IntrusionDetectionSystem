#combining all parts here in one single file

import socket
import struct 
import time
from collections import defaultdict
import logging # to log any possible intrusion
import json # to format in json form so it will make processing easier

#logging function
logging.basicConfig(
	filename='ids_alerts.log',
	level=logging.WARNING,
	format="%(asctime)s %(levelname)s %(message)s"
)

# function to log alerts
def alert(rule,src_ip,detail,severity=2):
	entry=json.dumps({
		'rule' : rule,
		'src': src_ip,
		'detail': detail,
		'severity': severity,
		'ts':time.time()
	})
	logging.warning(entry)
	print(f'[ALERT- {severity}] {rule} | {src_ip} | {detail}')

# raw socket opening
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(0x0003))

#for syn_packets to detect scans
syn_tracker=defaultdict(list)
threshold=20 #max number of seconds in a certain window
window=10 #seconds

# for icmp flood detection
icmp_tracker=defaultdict(list)
icmp_threshold=50
icmp_window=1

# for ssh brute force detection
ssh_tracker=defaultdict(list)
ssh_threshold=10
ssh_window=60

print("Listening..")

while True:
	raw_data, addr= s.recvfrom(65535) #capturing packets 
	#skipping ethernet header that are the first 14 bytes
	ip=raw_data[14:34]
	
	ip_header=struct.unpack("!BBHHHBBH4s4s",ip)
	
	version=ip_header[0] >> 4
	src=ip_header[8]
	dst=ip_header[9]
	protocol=ip_header[6]
	ttl=ip_header[5]

	src_ip=socket.inet_ntoa(src)
	dst_ip=socket.inet_ntoa(dst)
	#print( "Version: ",version, socket.inet_ntoa(src),"->",socket.inet_ntoa(dst)," Protocol: ",protocol, "TTL: ", ttl)
	# we commented out above print statement as we do not need that in IDS logic

	if protocol==6:
		tcp=raw_data[34:54]
		tcp_header=struct.unpack('!HHLLBBHHH',tcp)
		src_port=tcp_header[0]
		dst_port=tcp_header[1]
		flags=tcp_header[5]

		syn=(flags & 0x02) !=0
		ack=(flags & 0x10) !=0
		fin=(flags & 0x01) !=0
		rst=(flags & 0x04) !=0

		#print(f'TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} | SYN={syn} ACK={ack} FIN={fin} RST={rst}')
		#we do not need above printing line now

		#from here we are checking port scanning logic so we will just consider syn and ack
		#for that we have created syn_tracker, threshold and window

		if syn and not ack: #indicates that it was just scanning not trying to establish a connection, because then it could be logged
			now=time.time()
			syn_tracker[src_ip].append(now)
			syn_tracker[src_ip]=[
				t for t in syn_tracker[socket.inet_ntoa(src)]
				if now-t<window
			]

			if len(syn_tracker[socket.inet_ntoa(src)])>threshold:
				alert('PORT_SCAN', src_ip, f'{len(syn_tracker[src_ip])} SYNs in {window}s',severity=2)
						alert('PORT_SCAN', src_ip, f'{len(syn_tracker[src_ip])} SYNs in {window}s',severity=2)

		# for brute force detection
		dst_port=tcp_header[1]
		if syn and not ack and dst_port==22:
			now=time.time()
			ssh_tracker[src_ip].append(now)
			ssh_tracker[src_ip]=[
				t for t in ssh_tracker[src_ip] if now-t<ssh_window]
			if len(ssh_tracker[src_ip]) >ssh_threshold:
				alert('SSH BRUTE', src_ip, f'{len(ssh_tracker[src_ip])} SSH attempts in {ssh_window}s',severity=2)
	elif protocol==1:
		icmp=raw_data[34:38]
		icmp_header=struct.unpack('!BBH',icmp)
		icmp_type=icmp_header[0]

		if icmp_type==8: #indicates echo request
			now=time.time()
			icmp_tracker[src_ip].append(now)
			icmp_tracker[src_ip]=[
				t for t in icmp_tracker[src_ip] if now-t<icmp_window]
			if len(icmp_tracker[src_ip])>threshold:
				alert('ICMP FLOOD', src_ip, f'{len(icmp_tracker[src_ip])} pings in {icmp_window}s',severity=3)

