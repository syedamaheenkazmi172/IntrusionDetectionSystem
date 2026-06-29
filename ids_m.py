#combining all parts here in one single file

import socket
import struct 

s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(0x0003))

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
