#!/usr/bin/env python
#coding: utf-8
#yuanzhong.yuan

from bcc import BPF
import ctypes as ct
import argparse
import struct
import socket
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack


examples="""
        pstrace.py -H xxx.xxx.xxx.xxx
"""


parser = argparse.ArgumentParser(
     description="Trace any packet sending from user space to TCP/IP stack",
     formatter_class=argparse.RawDescriptionHelpFormatter,
     epilog=examples)

parser.add_argument("-H", "--ipaddr", type=str,
         help="ip address")
parser.add_argument("-P", "--port", type=int,default=0,
        help="tcp or udp port")

args = parser.parse_args()

ipaddr=(struct.unpack("I",socket.inet_aton("0" if args.ipaddr == None else args.ipaddr))[0])
port=(args.port)

bpf_def="#define TRACE_FILTER \n"
bpf_filters="#define ADDR_FILTER (0x%x)\n" % (ipaddr)
bpf_filters+="#define PORT_FILTER (%d)\n" % (port)

bpf_text=open(r"pstrace.c", "r").read()
bpf_text = bpf_def + bpf_text
bpf_text=bpf_text.replace("TRACE_FILTER_DEFINE", bpf_filters)


FUNCNAME_MAX_LEN = 64

class Data(ct.Structure):
    _fields_=[("pid",ct.c_uint),
            ("func_name",ct.c_char * FUNCNAME_MAX_LEN),
            #("ip_version",ct.c_ubyte),
            ("ip_version",ct.c_ubyte),
            ("protocol",ct.c_ubyte),
            ("saddr", ct.c_ulonglong),
            ("daddr", ct.c_ulonglong),
            ("sport",ct.c_ushort),
            ("dport",ct.c_ushort),
            ("tcpseq",ct.c_uint),
            ("stack_id",ct.c_uint),
            ]

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    if event.ip_version == 4:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr))
    else:
        return

    if event.protocol == socket.IPPROTO_TCP:
         pkt_info = ("%s:%u -> %s:%u seq:%-20s" % (saddr, event.sport, daddr, event.dport, event.tcpseq))

    print ("%-5d %-45s %-10s" % (event.pid,pkt_info, event.func_name))



print("%-5s %-45s %-10s" %("PID","PKT_INFO","FUNC"))

if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["ipv4_event_out"].open_perf_buffer(print_event)
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
