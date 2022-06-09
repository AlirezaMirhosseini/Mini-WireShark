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
