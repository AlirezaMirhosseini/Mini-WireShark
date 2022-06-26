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
    src_ip = src_ip + "{:02x}".format(i)
    
ip = inet_aton(lines[0])
dest_ip = str()
for i in ip:
    dest_ip = dest_ip + "{:02x}".format(i)

src_port = "%04x" % int(lines[3])
dest_port = "%04x" % int(lines[1])
interface0 = lines[4].strip()

send_syn(src_ip, src_port, dest_ip, dest_port, src_mac, dest_mac, interface0)