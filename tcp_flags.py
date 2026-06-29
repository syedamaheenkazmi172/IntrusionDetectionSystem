import socket, struct

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

while True:
    raw_data, _ = s.recvfrom(65535)
    ip_header = raw_data[14:34]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    if protocol == 6:
        tcp_header = raw_data[34:54]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        s_port = tcph[0]
        d_port = tcph[1]
        flags = tcph[5]
        syn = (flags & 0x02) != 0
        ack = (flags & 0x10) != 0
        fin = (flags & 0x01) != 0
        rst = (flags & 0x04) != 0
        print(f'TCP {src_ip}:{s_port} -> {dst_ip}:{d_port} | SYN={syn} ACK={ack} FIN={fin} RST={rst}')
