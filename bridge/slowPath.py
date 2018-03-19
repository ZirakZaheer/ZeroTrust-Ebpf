#!/usr/bin/env python
#
# tc_perf_event.py  Output skb and meta data through perf event
#
# Copyright (c) 2016-present, Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import ctypes as ct
import pyroute2
#import scapy
import socket


#bpf code (consider transferring this to a separate file

bpf_txt = """

#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/bpf.h>

// setup bpf perf event channel
BPF_PERF_OUTPUT(skb_events);

int handler(struct __sk_buff * skb) {
	void *data = (void *)(long) skb->data;
	void *data_end = (void *)(long)skb->data_end;
	// you can get header and data by defining offsets
	u32 metadata = 0xfaceb00c;

	skb_events.perf_submit_skb(skb, skb->len, &metadata, sizeof(metadata));

	return TC_ACT_OK;
}

"""
def resubmitSkb(packet, interface):
	sock = socket(AF_PACKET, SOCK_RAW)
	sock.bind((interface, 0))
	return sock.send(packet)


def userspace_packet_handler(cpu, data, size):
	class SkbEvent(ct.Structure):
		_fields_ = [ ("tag", ct.c_uint32),
			     ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32)))]
	#todo
	#cast contents of data to skb
	skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
	rawSkb  = skb_event.raw
	tag = skb_event.tag
	#parse those packets to see the size and mapping of the packets
	
	#executer actions
		#fetch context
		#context 
		#insert in local context table (in ebpf maps)
	
	#rebuild packet using scapy
		#require a raw socket and needs to know the interface to which to write packets
	resubmitSkb(rawSkb, "tap0")			

	#rebuild headers from the skb received 

try:
	b = BPF(text=bpf_txt)
	fn = b.load_func("handler", BPF.SCHED_CLS)

	ipr = pyroute2.IPRoute()
	
	# skipping initializing tap and setting up the ebpf code to run on tap interface

	b["skb_events"].open_perf_buffer(userspace_packet_handler)
	while True:
		b.perf_buffer_poll()
finally:
	print "Done"
	# clean up interfaces and print something useful 
