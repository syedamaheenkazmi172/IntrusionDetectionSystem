import socket, struct

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

while True:
	raw_data, _ = s.recvfrom(65535)
	ip_header = raw_data[14:34]
	iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
	protocol = iph[6]
	src_ip = socket.inet_ntoa(iph[8])
	dst_ip = socket.inet_ntoa(iph[9])
	print(f'{src_ip} -> {dst_ip} | protocol {protocol}')
