from socket import *
from struct import *

conn = socket(AF_PACKET, SOCK_RAW, ntohs(3))

def ether(data):
    dest_mac, src_mac, proto = unpack('! 6s 6s H', data[:14])
    
    bytes_str = map('{:02x}'.format, dest_mac)
    dest_mac_address = ':'.join(bytes_str).upper()
    
    bytes_str = map('{:02x}'.format, src_mac)
    src_mac_address = ':'.join(bytes_str).upper()
    
    return dest_mac_address, src_mac_address, htons(proto), data[14:]

def ip(data):
    version_internet_header_length = data[0]
    version = version_internet_header_length >> 4
    internet_header_length = (version_internet_header_length & 15) * 4
    ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, internet_header_length, ttl, proto, '.'.join(map(str, src)), '.'.join(map(str, target)), data[internet_header_length:]

def tcp(data):
    src_port, dest_port, sequence, ack, offset_reserved_flags = unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

while True:
    raw_data, addr = conn.recvfrom(65536)
    dest_mac, src_mac, ethernet_protocol, data = ether(raw_data)

    if ethernet_protocol == 8:
        (version, header_length, ttl, proto, src, target, data) = ip(data)

        if proto == 6:
                (src_port, dest_port, sequence, ack, urg, flagAck, flagpsh, flagRst, flagSyn, flagFin, data) = tcp(data)
                if(dest_port == 3000 and flagAck == 1 and flagSyn == 1):
                    src_ip_address = '.'.join(map(str, src))
                    dest_ip_address = '.'.join(map(str, target))
                    
                    src_ip_address = src_ip_address.replace('...', ' ')
                    src_ip_address = src_ip_address.replace('.', '')
                    src_ip_address = src_ip_address.replace(' ', '.')
                    
                    dest_ip_address = dest_ip_address.replace('...', ' ')
                    dest_ip_address = dest_ip_address.replace('.', '')
                    dest_ip_address = dest_ip_address.replace(' ', '.')
                    
                    print(f'\tPort {src_port} is open on {src_ip_address}')