from socket import *
from checksum3 import cs
from binascii import unhexlify

def ether_sender(message,interface):
    pkt = unhexlify(message)
    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((interface, 0))
    s.send(pkt)
    s.close()
    print(f'Send {int(len(message)/2)}-byte TCP SYN packet on {interface}')

def send_syn(src_ip, src_port, dest_ip, dest_port, src_mac, dest_mac, interface):
    proto3 = "0800"
    ver = "45"
    diff = "00"
    t_len = "0028"
    id = "07c3"
    flags = "4000"
    ttl = "40"
    proto4 = "06"
    cs3 = "0000"
    seq_num = "174930d1"
    ack = "00000000"
    h_len = "5002"
    w_size = "7210"
    cs4 = "0000"
    up = "0000"
    ip_seg = ver + diff + t_len + id + flags + ttl + proto4 + cs3 + src_ip + dest_ip
    ip_seg = ip_seg.replace(' ', '')
    ip_seg = " ".join(ip_seg[i:i + 2] for i in range(0, len(ip_seg), 2))
    cs3 = cs(ip_seg)
    print(f'on {dest_port}')
    tcp_seg = src_ip + dest_ip + "00" + proto4 + "00" + "14" + src_port + dest_port + seq_num + ack + h_len + w_size + "00 00" + up
    tcp_seg = tcp_seg.replace(' ', '')
    tcp_seg = " ".join(tcp_seg[i:i + 2] for i in range(0, len(tcp_seg), 2))
    cs4 = cs(tcp_seg)

    message = dest_mac + src_mac + proto3 + ver + diff + t_len + id + flags + ttl + proto4 + cs3 + src_ip + dest_ip + src_port + dest_port + seq_num + ack + h_len + w_size + cs4 + up
    message = message.replace(' ', '')
    ether_sender(message,interface)