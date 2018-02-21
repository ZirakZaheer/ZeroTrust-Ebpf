#!/usr/bin/env python

from bcc import BPF
from pyroute2 import IPRoute, IPDB
import sys
import logging

ipr = IPRoute()
ipdb = IPDB(nl=ipr)
docker0 = ipdb.interfaces.vethbc6947a
docker1 = ipdb.interfaces.vethcf3f006


bpf_text = """
#include <bcc/proto.h>
#include <uapi/linux/in.h>
#include "openstate.h"

int ebpf_filter(struct __sk_buff *skb) {

 bpf_trace_printk("skb ifindex %llu\\n", skb->ifindex);

 return TC_CLS_NOMATCH;
}
"""


b = BPF(text=bpf_text)

fn = b.load_func("ebpf_filter", BPF.SCHED_CLS)

ipr.tc("add", "ingress", docker0.index, "ffff:")
ipr.tc("add-filter", "bpf", docker0.index, ":1", fd=fn.fd,
        name=fn.name, parent="ffff:", action="drop", classid=1)
ipr.tc("add", "ingress", docker1.index, "ffff:")
ipr.tc("add-filter", "bpf", docker1.index, ":1", fd=fn.fd,
        name=fn.name, parent="ffff:", action="drop", classid=1)

print("eBPF ifindex %d" % docker0.index)
print("eBPF ifindex %d" % docker1.index)


try:
    print "Ready..."
    while 1:
       (task, pid, cpu, flags, ts, msg) = b.trace_fields()
       print("%s %s" % (ts, msg))
except KeyboardInterrupt:
    print "Ending..."
finally:
    ipr.tc("del", "ingress", docker0.index, "ffff:")
    ipr.tc("del", "ingress", docker1.index, "ffff:")
    ipdb.release()
    print("Cleaned.")

