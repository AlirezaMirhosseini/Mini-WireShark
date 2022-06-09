from socket import *
from struct import *

def MacAddress(address): # from https://stackoverflow.com/questions/159137/getting-mac-address
    bytes_string = map('{:02x}'.format, address)
    mac_address = ':'.join(bytes_string).upper()
    return mac_address

def ether(data):
    dest_mac, src_mac, proto = unpack('! 6s 6s H', data[:14])
    return MacAddress(dest_mac), MacAddress(src_mac), htons(proto), data[14:]

def ipv4_address(address):
    return '.'.join(map(str, address))

def ip(data):
    version_internet_header_length = data[0]
    version = version_internet_header_length >> 4
    internet_header_length = (version_internet_header_length & 15) * 4
    ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, internet_header_length, ttl, proto, ipv4_address(src), ipv4_address(target), data[internet_header_length:]
    
def tcp(data):
    src_port, dest_port, sequence, ack, offset_reserved_flags = unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return (src_port, dest_port, sequence, ack, data[offset:])

conn = socket(AF_PACKET, SOCK_RAW, ntohs(3))

while True:
    raw_data, address = conn.recvfrom(65536)
    dest_mac, src_mac, ethernet_protocol, data = ether(raw_data)

    if ethernet_protocol == 8:
        (version, header_length, ttl, proto, src, target, data) = ip(data)

        if proto == 6:
            (src_port, dest_port, sequence, ack, data) = tcp(data)

            if(src_port == 80 or dest_port == 80):
                print('\tTCP Segment:')
                print(f'\t\tSource Port: {src_port} / Destination Port: {dest_port}')
                print(f'\t\tSequence: {sequence} / Ack: {ack}')