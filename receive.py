#!/usr/bin/env python3

import sys
from scapy.all import sniff, get_if_list
import socket

HOST = '10.1.1.1'
PORT = 53

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((HOST, PORT))

def handle_pkt(pkt):
    print("got a packet")
    #pkt.show2()
    sys.stdout.flush()


def main():
    print('server start at: %s:%s' % (HOST, PORT))
    print('wait for connection...')
    iface = 'eth0'
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    while True:
        sniff(iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
