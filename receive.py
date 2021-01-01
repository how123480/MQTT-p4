#!/usr/bin/env python
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import IP, UDP, Raw, Ether, TCP
from scapy.layers.inet import _IPOption_HDR
from scapy.fields import *

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):
    print "got a packet"
    pkt.show2()
#    hexdump(pkt)
    sys.stdout.flush()

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
    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter = 'ether proto 0x1234',iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
