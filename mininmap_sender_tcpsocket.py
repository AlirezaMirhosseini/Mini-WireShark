import imp
from socket import *
from syn_send import send_syn

fd = open('info.txt', 'r')
lines = fd.readlines()
for i in range(len(lines)):
    lines[i] = lines[i].strip('\n')
    
dest_mac = lines[6][:17]
src_mac = lines[5][:17]
ip = inet_aton(lines[2])
src_ip = str()
for i in ip:
    src_ip += "{:02x}".format(i)
    
dest_ip_decimal = input('What is the target IP address? (default = 93.184.216.34)')
if not dest_ip_decimal:
    dest_ip_decimal = "93.184.216.34"

dest_ip_decimal = inet_aton(dest_ip_decimal)
dest_ip = str()
for i in dest_ip_decimal:
    dest_ip += "{:02x}".format(i)

src_port = "%04x" % int(lines[3])
interface0 = lines[4].strip()
dest_ports = input('Which ports do you want to scan? ')
dest_ports = dest_ports.split('-')
for dest_port in range(int(dest_ports[0]), int(dest_ports[1]) + 1):
    send_syn(src_ip, src_port, dest_ip, "%04x" % dest_port, src_mac, dest_mac, interface0)