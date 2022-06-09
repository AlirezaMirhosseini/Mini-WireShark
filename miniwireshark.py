from socket import *
from struct import unpack
import re

def mac_address(address): # from https://stackoverflow.com/questions/4959741/python-print-mac-address-out-of-6-byte-string
    return "%x:%x:%x:%x:%x:%x" % unpack("BBBBBB",address)

def ether(data):
    dest_mac, src_mac, proto = unpack('!6s 6s H', data[:14])
    dest_mac = ':'.join(re.findall('..', dest_mac.encode('hex')))
    src_mac = ':'.join(re.findall('..', src_mac.encode('hex')))

    return [dest_mac, src_mac, hex(proto), data[14:]]

def ip(data):
    maindata = data
    data = unpack('! B s H 2s 2s B B 2s 4s 4s', data[:20])
    
    return [data[0] >> 4,              #version
    (data[0] & (0x0F)) * 4,            #header length
    "0x" + data[1].encode('hex'),      #Diffserv
    data[2],                           #total length
    "0x" + data[3].encode('hex'),      #ID
    "0x" + data[4].encode('hex'),      #flags
    data[5],                           #ttl
    data[6],                           #protocol
    "0x" + data[7].encode('hex'),      #check sum
    socket.inet_ntoa(data[8]),         #source ip
    socket.inet_ntoa(data[9]),         #destination ip
    maindata[(data[0] & (0x0F)) * 4:]] #ip payload

conn = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
while True:
    raw_dat, add = conn.recvfrom(65535)
    ether_shark = ether(raw_dat)
    if(ether_shark[2] == "0x800"):
        ip_shark = ip(ether_shark[3])