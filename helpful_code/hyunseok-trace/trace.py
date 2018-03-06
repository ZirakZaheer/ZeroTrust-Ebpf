#!/usr/bin/python

from __future__ import print_function
from bcc import BPF

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);

int kprobe__inet_csk_accept(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();
	currsock.update(&pid, &sk);

	return 0;
};

int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
                bpf_trace_printk("null skpp\\n");
		return 0;
	}

	struct sock *skp = *skpp;
        struct net *net_ns = skp->__sk_common.skc_net.net;
	u32 saddr = skp->__sk_common.skc_rcv_saddr;
	u32 daddr = skp->__sk_common.skc_daddr;
	u16 dport = skp->__sk_common.skc_dport;
        u16 sport = skp->__sk_common.skc_num;
        unsigned int inum = net_ns->ns.inum;

        if (net_ns) {
	    bpf_trace_printk("inet_csk_accept: inum %u pid %u\\n", inum, pid);
        } else {
	    bpf_trace_printk("NULL net_ns\\n");
        }
	bpf_trace_printk("inet_csk_accept: sport %u dport %u\\n", sport, dport);

	currsock.delete(&pid);

	return 0;
}

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();
	currsock.update(&pid, &sk);

	return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
                bpf_trace_printk("null skpp\\n");
		return 0;
	}

        struct sock *skp = *skpp;
        struct net *net_ns = skp->__sk_common.skc_net.net;
	u32 saddr = skp->__sk_common.skc_rcv_saddr;
	u32 daddr = skp->__sk_common.skc_daddr;
	u16 dport = skp->__sk_common.skc_dport;
        u16 sport = skp->__sk_common.skc_num;
        unsigned int inum = net_ns->ns.inum;

        if (net_ns) {
	    bpf_trace_printk("tcp_v4_connect: inum %u pid %u\\n", inum, pid);
        } else {
	    bpf_trace_printk("NULL net_ns\\n");
        }
	bpf_trace_printk("tcp_v4_connect: sport %u dport %u\\n", sport, ntohs(dport));

	currsock.delete(&pid);

	return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)

while 1:
	try:
	    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
	except ValueError:
	    # Ignore messages from other tracers
	    continue

	print("%s" % msg)

