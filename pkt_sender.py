from socket import *
from binascii import unhexlify
message = input('What is your packet content? ')
#pkt = " ".join(message[i:i+2] for i in range(0,len(message),2))
interface = input('Which interface do you want to use? ')
pkt = unhexlify(message)
s = socket(AF_PACKET, SOCK_RAW)
s.bind((interface, 0))
print(pkt)

s.send(pkt)