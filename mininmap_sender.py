from socket import *
from pkt_sender import ether_sender
from checksum import cs_calc
from getmac import get_mac_address

fd = open('info.txt', 'r')
lines = fd.readlines()
for i in range(len(lines)):
    lines[i] = lines[i].strip('\n')
# dest_mac = lines[6][:17]
src_mac = lines[5][:17]
proto3 = "0800"
ver = "45"
diff = "00"
t_len = "0028"
id = "07c3"
flags = "4000"
ttl = "40"
proto4 = "06"
cs3 = "0000"
ip = inet_aton(lines[2])
src_ip = str()
for i in ip:
    src_ip = src_ip + "{:02x}".format(i)
# src_ip = int(inet_aton(lines[2]),16)#.encode("hex")
dest_ip_decimal = input('What is the target IP address? ')
dest_mac = get_mac_address(ip = dest_ip_decimal)
dest_ip_decimal = inet_aton(dest_ip_decimal)
dest_ip = str()
for i in dest_ip_decimal:
    dest_ip = dest_ip + "{:02x}".format(i)
# dest_ip = str(inet_aton(lines[0]),'utf-8')#.encode("hex")

src_port = "%04x" %int(lines[3])
# dest_port = "%04x" %int(lines[1])
seq_num = "174930d1"
ack = "00000000"
h_len = "5002"
w_size = "7210"
cs4 = "0000"
up = "0000"

interface0 = lines[4].strip()

dest_ports = input('Which ports do you want to scan? ')
dest_ports = dest_ports.split('-')
for dest_port in range(int(dest_ports[0]),int(dest_ports[1])+1):
    dest_port = "%04x" %(dest_port)
    ip_seg = ver+diff+t_len+id+flags+ttl+proto4+cs3+src_ip+dest_ip
    ip_seg = ip_seg.replace(' ','')
    ip_seg = " ".join(ip_seg[i:i+2] for i in range(0, len(ip_seg), 2))
    if(len(ip_seg)%2 == 1):
        ip_seg += ' '
    cs3N = cs_calc(ip_seg)
    cs3 = "{:04x}".format(cs3N)
    
    tcp_seg = src_ip+dest_ip+"00"+proto4+"00"+"14"+src_port+dest_port+seq_num+ack+h_len+w_size+"00 00"+up
    tcp_seg = tcp_seg.replace(' ','')
    tcp_seg = " ".join(tcp_seg[i:i+2] for i in range(0, len(tcp_seg), 2))
    if(len(tcp_seg)%2 == 1):
        tcp_seg += ' '
    cs4N = cs_calc(tcp_seg)
    cs4 = "{:04x}".format(cs4N)
    
    
    message = dest_mac+src_mac+proto3 +ver +diff+t_len +id+flags+ttl+proto4+cs3+src_ip+dest_ip+src_port+dest_port +seq_num+ack +h_len+w_size +cs4 +up
    message = message.replace(' ','')
    ether_sender(message,interface0)