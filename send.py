#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import ByteField, BitField
class Alarm(Packet):
    name = 'alarm_header'
    fields_desc = [ ByteField("isSuspectList", 0)]
class SuspectList(Packet):
    name = 'suspect_list'
    fields_desc = [ BitField("list0_high", 0, 256),
                    BitField("list0_low", 0, 256),
                    BitField("list1_high", 0, 256),
                    BitField("list1_low", 0, 256),
                    BitField("list2_high", 0, 256),
                    BitField("list2_low", 0, 256),
                    BitField("list3_high", 0, 256),
                    BitField("list3_low", 0, 256)]

class RemovedIp(Packet):
    name = 'removed_ip'
    fields_desc = [ BitField("removed_ip", 0, 32)]

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print(("sending on interface %s to %s" % (iface, str(addr))))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
