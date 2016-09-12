#! /usr/bin/env python

import socket

import os
import platform
import sys
import getopt
import struct
from ctypes import *



class TCP(Structure):
    _fields_ = [
        #("error", c_int),
        #("msg", nlmsghdr)
    ]
