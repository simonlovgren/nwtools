#! /usr/bin/env python

import socket

import os
import sys
import getopt
import struct
from ctypes import *
import fcntl

## SETTINGS
host = "127.0.0.1"

# Netlink for setting promiscuous mode on unix/linux
class ifreq(Structure):
    _fields_ = [("ifr_ifrn", c_char * 16),
                ("ifr_flags", c_short)]

IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

    
# IP Header
class IPv4(Structure):
    _fields_ = [
        #("name",        datatype, count),
        #("",            c_, ),
        ("version",      c_ubyte, 4),
        ("ihl",          c_ubyte, 4),
        ("dscp",         c_ubyte, 6),
        ("ecn",          c_ubyte, 2),
        #("tos",          c_ubyte),
        ("len",          c_ushort),
        ("id",           c_ushort),
        ("flags",        c_ubyte, 3),
        ("offset",       c_ushort, 13),
        ("ttl",          c_ubyte),
        ("protocol_num", c_ubyte),
        ("chksum",       c_ushort),
        ("src",          c_uint32),
        ("dst",          c_uint32)
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



def main(args):
    global host
    
    # Set correct socket type depending on OS
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

        # Set up sniffer
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # If on windows, set promiscuous mode through exposed api
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        #else:
            # Set promiscuous on other (unix/linux/etc.)
            #s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM)
            #ifr = ifreq()
            #ifr.ifrn = "eth4"
            #fcntl.ioctl(sniffer.fileno(), SIOCGIFFLAGS, ifr) # G for get
            #ifr.ifr_flags |= IFF_PROMISC
            #fcntl.ioctl(sniffer.fileno(), SIOCSIFFLAGS, ifr) # S for set
            
        try:
            lines = 0
            while True:
                # Read packet
                raw_buffer = sniffer.recvfrom(65565)[0]
        
                # Create IP header from first 20 bytes
                ip_header = IPv4(raw_buffer[0:20])

                #print header
                if(lines % 10 == 0):
                    print ""
                    print "#\tProtocol\tfrom IP\t\tto IP\t\tversion\tlength\tttl\tchksum\tflags"
                    print "----------------------------------------------------------------------------------"
                    
                # Print stuff
                print ("%d\t%s\t\t%s -> %s\t%d\t%d\t%d\t%d\t%s" %
                       (lines,
                        ip_header.protocol,
                        ip_header.src_address,
                        ip_header.dst_address,
                        ip_header.version,
                        ip_header.len,
                        ip_header.ttl,
                        ip_header.chksum,
                        "{0:b}".format(ip_header.flags)))
                    
                # Count up lines
                lines += 1
                    
        # Handle CTRL+C
        except KeyboardInterrupt:
            # If on windows, disable promiscuous mode
            if os.name == "nt":
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            #else:
                # Disable promiscuous on other (unix/linux/etc.)
                #s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM)
                #ifr = ifreq()
                #ifr.ifrn = "en0"
                #fcntl.ioctl(sniffer.fileno(), SIOCGIFFLAGS, ifr) # G for get
                #ifr.ifr_flags &= ~IFF_PROMISC
                #fcntl.ioctl(sniffer.fileno(), SIOCSIFFLAGS, ifr) # S for set
            
            print ""
            print "stopping..."

def parseOpts(argv):
    global host
    
    # Get name of script
    fn = os.path.basename(argv[0])
    
    #Extract options and arguments
    try:
        opts, args = getopt.getopt(argv[1:], "h", ["help"])
    except Exception:
        printHelp(fn, 2)

    # Parse options
    for opt, arg in opts:
        if opt == "--help" or opt == "-h":
            printHelp(fn, 0)

    # Check arguments match expected number
    if len(args) != 1:
        printHelp(fn, 2)

    host = args[0]
        
def printHelp(filename, status):
    print "usage: python " + filename + " 192.168.0.1"
    sys.exit(status)
    
if __name__ == "__main__":
    print "OS: " + os.name
    args = sys.argv[0:]
    parseOpts(args)
    main(args)
