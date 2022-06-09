from socket import *
from struct import *

conn = socket(AF_PACKET, SOCK_RAW, ntohs(3))

def MacAddress(address): # from https://stackoverflow.com/questions/159137/getting-mac-address
    bytes_string = map('{:02x}'.format, address)
    mac_address = ':'.join(bytes_string).upper()
    return mac_address

def ether(data):
    dest_mac, src_mac, proto = unpack('! 6s 6s H', data[:14])
    return MacAddress(dest_mac), MacAddress(src_mac), htons(proto), data[14:]

def ipv4_address(address):
    return '.'.join(map(str, address))

def ipv4_packet(data):
    version_internet_header_length = data[0]
    version = version_internet_header_length >> 4
    internet_header_length = (version_internet_header_length & 15) * 4
    ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, internet_header_length, ttl, proto, ipv4_address(src), ipv4_address(target), data[internet_header_length:]