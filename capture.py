import socket

s = socket.socket(socket.AF_PACKET,
                  socket.SOCK_RAW,
                  socket.ntohs(0x0003))

print('Listening for Packets...')
while True:
    raw_data, addr = s.recvfrom(65535)
    print(f'Packet: {len(raw_data)} bytes from interface {addr[0]}')
