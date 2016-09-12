#! /usr/bin/env python

import socket

import os
import platform
import sys
import getopt
import struct
from ctypes import *


## INFO
# http://lxr.free-electrons.com/source/include/uapi/linux/netlink.h#L52

# ===========
# CONSTANTS
# ===========

## Alignments
NLMSG_ALIGNTO = 4


## Flags
# Standard flag bits in nlmsg_flags
# ---------------------------------
# Must be set on all request messages.
NLM_F_REQUEST        = 1
# The message is part of a multipart message terminated by NLMSG_DONE.
NLM_F_MULTI          = 2
# Request for an acknowledgment on success.
NLM_F_ACK            = 4
# Echo this request.
NLM_F_ECHO           = 8
# Dump was inconsistent due to sequence change
NLM_F_DUMP_INTR      = 16
# Dump was filtered as requested
NLM_F_DUMP_FILTERED  = 32

# Additional flag bits for GET requests
# -------------------------------------
# Return the complete table instead of a single entry.
NLM_F_ROOT    =  0x100
# Return all entries matching criteria passed in message content.
# Not implemented yet.
NLM_F_MATCH   =  0x200
# Return an atomic snapshot of the table.
NLM_F_ATOMIC  =  0x400
# Convenience macro; equivalent to (NLM_F_ROOT|NLM_F_MATCH).
NLM_F_DUMP    =  (NLM_F_ROOT|NLM_F_MATCH)

#Note that NLM_F_ATOMIC requires the CAP_NET_ADMIN capability or an
#effective UID of 0.

# Additional flag bits for NEW requests
# -------------------------------------
# Replace existing matching object.
NLM_F_REPLACE =   0x100
# Don't replace if the object already exists.
NLM_F_EXCL    =   0x200
# Create object if it doesn't already exist.
NLM_F_CREATE  =   0x400
# Add to the end of the object list.
NLM_F_APPEND  =   0x800


## STRUCTS
class nlmsghdr(Structure):
    _fields_ = [
        #("name",        datatype, count),
        #("",            c_, ),
        ("len",          c_uint32), # Length of message incl. header
        ("type",         c_uint16), # Type of message content
        ("flags",        c_uint16), # Additional flags
        ("seq",          c_uint32), # Sequence number
        ("pid",          c_uint32)  # Sender port ID
    ]

#    def __new__(self):
#        return self
#
#    def __init__(self, socket_buffer = None):
#        # Map protocol to name

class nlmsgerr(Structure):
    _fields_ = [
        ("error", c_int), # Negative errno or 0 for ACK
        ("msg", nlmsghdr) # Message header that caused the error
    ]
