#! /usr/bin/env python

import socket

import os
import struct
from ctypes import *


## SETTINGS
host = "192.168.0.104"

# IP Header
class IPv4(Structure):
    _fields = [
        #("name", datatype, count),
        #("", c_, ),
        ("version", c_ubyte, 4),
        ("ihl", c_ubyte, 4),
        #("dscp", c_ubyte, 6),
        #("ecn", c_ubyte, 2),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        #("flags", c_ubyte, 3),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("chksum", c_ushort),
        ("src", c_ulong),
        ("dst", c_ulong)
    ]

    def __new__(self, socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer = None):
        # Map protocol to name
        self.protocol_map = {1: "ICMP", 2: "TCP", 3:"UDP"}

        # Human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        # Human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)



# Set correct socket type depending on OS
if os.name == "nt":
    soclet_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

# Set up sniffer
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# If on windows, set promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
    while True:
        # Read packet
        raw_buffer = sniffer.recvfrom(65565)[0]

        # Create IP header from first 20 bytes
        ip_header = IP(raw_buffer[0:20])

        # Print stuff
        print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)

# Handle CTRL+C
except KeyboardInterrupt:
    # If on windows, disable promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    print ""
    print "stopping..."
