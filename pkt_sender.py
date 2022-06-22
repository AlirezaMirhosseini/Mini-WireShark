from socket import *
from binascii import unhexlify
def ether_sender(message, interface):
    pkt = unhexlify(message)
    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((interface, 0))
    s.send(pkt)
    s.close()
    print(f'Send {int(len(message)/2)}-byte packet on {interface}')
if __name__ == "__main__":
    message = input('What is your packet content? ')
    interface = input('Which interface do you want to use? ')
    ether_sender(message,interface)