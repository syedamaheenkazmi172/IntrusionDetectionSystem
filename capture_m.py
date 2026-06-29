import socket

s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x003))

print('Listening to packets')

while True:
	raw_data,addr=s.recvfrom(65535)
	print(f'Packet: {len(raw_data)} from interface {addr[0]}')
