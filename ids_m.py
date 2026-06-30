#combining all parts here in one single file

import socket
import struct 
import time
from collections import defaultdict

s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(0x0003))

#for syn_packets to detect scans
syn_tracker=defaultdict(list)
threshold=20 #max number of seconds in a certain window
window=5 #seconds

print("Listening..")

while True:
	raw_data, addr= s.recvfrom(65535) #capturing packets 
	#skipping wthernet header that are the first 14 bytes
	ip=raw_data[14:34]
	
	ip_header=struct.unpack("!BBHHHBBH4s4s",ip)
	
	version=ip_header[0] >> 4
	src=ip_header[8]
	dst=ip_header[9]
	protocol=ip_header[6]
	ttl=ip_header[5]
	print(
	 "Version: ",version, socket.inet_ntoa(src),"->",socket.inet_ntoa(dst)," Protocol: ",protocol, "TTL: ", ttl)
	

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
		
		print(f'TCP {socket.inet_ntoa(src)}:{src_port} -> {socket.inet_ntoa(dst)}:{dst_port} | SYN={syn} ACK={ack} FIN={fin} RST={rst}')
		

		#from here we are checking port scanning logic so we will just consider syn and ack
		#for that we have created syn_tracker, threshold and window
		
		if syn and not ack: #indicates that it was just scanning not trying to establish a connection, because then it could be logged
			now=time.time()
			syn_tracker[socket.inet_ntoa(src)].append(now)
			syn_tracker[socket.inet_ntoa(src)]=[
				t for t in syn_tracker[socket.inet_ntoa(src)]
				if now-t<window
			]
			
			if len(syn_tracker[socket.inet_ntoa(src)])>threshold:
				print(f'[ALERT] PORT_SCAN from {socket.inet_ntoa(src)} - {len(syn_tracker[socket.inet_ntoa(src)])} SYNs in {window}s')
