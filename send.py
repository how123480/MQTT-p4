#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, TCP
from scapy.fields import *
import readline

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class MQTT(Packet):
    fields_desc = [ BitField("message_type", 0, 4),
                    BitField("DUP", 0, 1),
                    BitField("QoS", 0, 2),
                    BitField("R", 0, 1)]

class Topic(Packet):
   fields_desc = [ BitField("topic", 0, 16),
                   BitField("debug",0, 32)]


bind_layers(Ether, MQTT, type=0x1234)
bind_layers(MQTT, Topic)
bind_layers(Topic, IP)

def main():

    if len(sys.argv)<2:
        print 'pass 2 arguments: <destination>'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print "sending on interface %s to %s" % (iface, str(addr))

    while True:
        print
        s = str(raw_input('Define Message Type: 3(PUB), 8(SUB), 10(UNSUB) '))
        if s == "q":
            break;
        print

        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff');
        try:
            pkt = pkt / MQTT(message_type=int(s), DUP=0, QoS=0, R=0)
        except ValueError as e:
            print '[MQTT]' + e
            pass

        s = str(raw_input('Define Topic Type: 0~2^16-1 '))
        if s == "q":
            break;
        print
        try:
            pkt = pkt / Topic(topic=int(s), debug=int(0))
        except ValueError as e:
            print '[Topic]' + e
            pass

        pkt = pkt / IP(dst=addr) / TCP(dport=4321, sport=1234)
        pkt.show2()
        sendp(pkt, iface=iface, verbose=True)

if __name__ == '__main__':
    main()
