import struct
import socket

#input is a hex stream (with white spaces among bytes) containg tcp or ip relevant fields
#For tcp, the input is the hex stream of: src_ip,dest_ip,"00",proto4,"00","14",src_port,dest_port,seq_num,ack,h_len,w_size,"00 00",up
#For IP, the input is the hex stream of: ver,diff,t_len,id,flags,ttl,proto4,cs3,src_ip,dest_ip
def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def cs_calc(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff

def cs(data): 
    data = data.split()
    data = map(lambda x: int(x,16), data)
    data = struct.pack("%dB" % len(data), *data)
    return "%04x " % socket.ntohs(cs_calc(data))
