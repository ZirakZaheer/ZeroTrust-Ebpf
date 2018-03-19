#!/usr/bin/env python
#
# tc_perf_event.py  Output skb and meta data through perf event
#
# Copyright (c) 2016-present, Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import ctypes as ct
import pyroute2
from socket import *
from pytap2 import *
import os
from fcntl import ioctl
bpf_txt = """
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/bpf.h>

BPF_PERF_OUTPUT(skb_events);

struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};

int handle_egress(void *skb2)
{
	struct __sk_buff * skb = (struct __sk_buff *) skb2;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct eth_hdr *eth = data;
	struct ipv6hdr *ip6h = data + sizeof(*eth);
	u32 magic = 0xfaceb00c;

	/* single length check */
	if (data + sizeof(*eth) + sizeof(*ip6h) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto == htons(ETH_P_IPV6) &&
	    ip6h->nexthdr == IPPROTO_ICMPV6)
	        skb_events.perf_submit_skb(skb, skb->len, &magic, sizeof(magic));

	return TC_ACT_OK;
}"""

TUNSETIFF = 0x400454ca
TUNSETOWNER = TUNSETIFF + 2
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

# Open file corresponding to the TUN device.

def tapDev(tapname, mode):
    tap = os.open('/dev/net/tun', mode | os.O_NONBLOCK)
    ifr = struct.pack('16sH', tapname, IFF_TAP | IFF_NO_PI)
    ioctl(tap, TUNSETIFF, ifr)
    return tap

# demo packet to test that tap device is working correctly
icmp_req = b'E\x00\x00(\x00\x00\x00\x00@\x01`\xc2\n\x00\x00\x04\x08\x08'\
    '\x08\x08\x08\x00\x0f\xaa\x00{\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00test'
#os.write(ftun, icmp_req)

openedDev = tapDev('tap0', os.O_RDWR)
print openedDev
os.write(openedDev, icmp_req)

# we dont need this function because you can write to tap device direct using os.write once it has been opened correctly
def resubmitSkb(packet, interface):
        sock = socket(AF_PACKET, SOCK_RAW)
        sock.bind((interface, 0))
	print sock
        return sock.send(packet)
def print_skb_event(cpu, data, size):
    class SkbEvent(ct.Structure):
        _fields_ =  [
			("magic", ct.c_uint32),
			("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32)))
		    ]
    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    icmp_type = int(skb_event.raw[54])
    # Only print for echo request
    print bytes(skb_event.raw)
    os.write(openedDev, skb_event.raw)    
    print icmp_type
    if icmp_type == 128:
        src_ip = bytes(skb_event.raw[22:38])
        dst_ip = bytes(skb_event.raw[38:54])
    #    print("%-3s %-32s %-12s 0x%08x" %
     #         (cpu, socket.inet_ntop(socket.AF_INET6, src_ip),
      #         socket.inet_ntop(socket.AF_INET6, dst_ip),
       #        skb_event.magic))

try:
    b = BPF(text=bpf_txt)
    fn = b.load_func("handle_egress", BPF.SCHED_CLS)

    ipr = pyroute2.IPRoute()
    ipr.link("add", ifname="me", kind="veth", peer="you")
    me = ipr.link_lookup(ifname="me")[0]
    you = ipr.link_lookup(ifname="you")[0]
    for idx in (me, you):
        ipr.link('set', index=idx, state='up')

    ipr.tc("add", "clsact", me)
    ipr.tc("add-filter", "bpf", me, ":1", fd=fn.fd, name=fn.name,
           parent="ffff:fff3", classid=1, direct_action=True)

    b["skb_events"].open_perf_buffer(print_skb_event)
    print('Try: "ping -6 ff02::1%me"\n')
    print("%-3s %-32s %-12s %-10s" % ("CPU", "SRC IP", "DST IP", "Magic"))
    while True:
        b.perf_buffer_poll()
finally:
    if "me" in locals(): ipr.link("del", index=me)
