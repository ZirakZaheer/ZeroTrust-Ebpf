from bcc import BPF,table, libbcc
import ctypes as ct
import re
import os

prog = """
#include <linux/pid.h>
#include <linux/sched.h>
//#include "bpf_elf.h"
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <net/net_namespace.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <uapi/linux/ptrace.h>

struct data_t {
 u32 pid;
 u64 inum;
 u64 lport;
 char comm[TASK_COMM_LEN];
};

/*
struct bpf_elf_map __section("maps") DEMO_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct data_t),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 1024,
};
*/
BPF_HASH(currsock, u32, struct sock *);

BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(events1);
BPF_TABLE_PUBLIC("hash", u32, struct data_t, DEMO_MAP, 1024);


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
	struct data_t data = {};
	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
                bpf_trace_printk("null skpp\\n");
		return 0;
	}

	struct sock *skp = *skpp;
        int ifindex = skp->sk_bound_dev_if;     
	struct net *net_ns = skp->__sk_common.skc_net.net;
	u32 saddr = skp->__sk_common.skc_rcv_saddr;
	u32 daddr = skp->__sk_common.skc_daddr;
	u16 dport = skp->__sk_common.skc_dport;
   	u16 sport = skp->__sk_common.skc_num;
    	unsigned int inum = net_ns->ns.inum;

    if (net_ns) {
//	    bpf_trace_printk("inet_csk_accept: inum %u pid %u ifindex %d \\n", inum, pid, ifindex);
    } else {
//	    bpf_trace_printk("NULL net_ns\\n");
    }
	data.pid = pid;
	data.lport = sport;
	data.inum = inum;
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	bpf_trace_printk("inet_csk_accept: sport %u dport %u\\n", sport, dport);
	events.perf_submit(ctx, &data, sizeof(data));
	currsock.delete(&pid);
	DEMO_MAP.lookup_or_init(&data.lport, &data);
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
	struct data_t data = {};
	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
                bpf_trace_printk("null skpp\\n");
		return 0;
	}

        struct sock *skp = *skpp;
        //get interface sock is bound to
	int ifindex = skp->sk_bound_dev_if;	
	struct net *net_ns = skp->__sk_common.skc_net.net;
		u32 saddr = skp->__sk_common.skc_rcv_saddr;
		u32 daddr = skp->__sk_common.skc_daddr;
		u16 dport = skp->__sk_common.skc_dport;
        u16 sport = skp->__sk_common.skc_num;
        unsigned int inum = net_ns->ns.inum;
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
        if (net_ns) {
	    	bpf_trace_printk("tcp_v4_connect: inum %u pid %u\\n", inum, pid);
        } else {
	    	bpf_trace_printk("NULL net_ns\\n");
        }
	data.pid = pid;
        data.lport = sport;
        data.inum = inum;
	bpf_trace_printk("tcp_v4_connect: sport %u dport %u  ifindex %d\\n", sport, ntohs(dport), ifindex);
        events.perf_submit(ctx, &data, sizeof(data));
	DEMO_MAP.lookup_or_init(&data.lport, &data);
	currsock.delete(&pid);

	return 0;
}


int kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock, int backlog) {
	struct data_t data = {};
	struct task_struct *task;
	struct nsproxy* nsproxy;
	struct net* docker_ns;
	u64 sock_cookie = 0;
	data.pid = bpf_get_current_pid_tgid();
	//data.ts = bpf_ktime_get_ns();
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	task =  (struct task_struct*) bpf_get_current_task();
	//	sock_cookie = bpf_get_socket_cookie();
	//      data.cookie = sock_cookie;
	nsproxy = task->nsproxy;
	data.inum = nsproxy->net_ns->ns.inum;
        //data.inum = docker_ns;
	
	
	struct sock *sk = sock->sk;
	struct inet_sock *inet = (struct inet_sock *)sk;
	data.lport = inet->inet_sport;
	data.lport = ntohs(data.lport);
	events.perf_submit(ctx, &data, sizeof(data));
	//bpf_lookup_elem(DEMO_MAP, &data.pid, &data);
	//	u32 psNum = 1000;	
	DEMO_MAP.lookup_or_init(&data.lport, &data);
	

	return 0;

}

"""
b = BPF(text=prog)
#b.attach_kprobe(event="sock_register", fn_name="hello")
#b.attach_kprobe(event="SyS_execve",fn_name="hello")
#b.attach_kprobe(event="sys_socketcall",fn_name="hello")
#b.attach_kprobe(event="unix_socketpair",fn_name="hello")

TASK_COMM_LEN = 16
class Policy(ct.Structure):
	_fields_ = [("pid", ct.c_ulonglong),
		    ("dport",ct.c_ulonglong),
		    ("srcContext",ct.c_char * TASK_COMM_LEN),
		    ("dstContext",ct.c_char * TASK_COMM_LEN)]


class Data(ct.Structure):
	_fields_ = [("pid", ct.c_ulonglong),
		    ("inum", ct.c_ulonglong),
		    ("lport", ct.c_ulonglong),
		    ("comm", ct.c_char *  TASK_COMM_LEN)]
		    #("tagetNS",ct.Structure)]
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

class PinnedMap(table.HashTable):
        def __init__(self,map_path, keyType, valueType,maxEntries):
                map_fd = libbcc.lib.bpf_obj_get(ct.c_char_p(map_path))
                if map_fd < 0:
                        raise ValueError("failed to open map")
                self.map_fd = map_fd
                self.Key = keyType
                self.Leaf = valueType
                self.max_entries = maxEntries





start = 0

def handle_event(cpu, data, size):
	global start
	event = ct.cast(data, ct.POINTER(Data)).contents
	if event.comm != "sshd":
		print("%-10d %-16s %-6d %-10d %s"  % (event.lport, event.comm, event.pid, event.inum, "Hello, perf_output!"))
		findNSpid(event.pid)	
		
		# make the map available clusterwide
		demoMap = b.get_table("DEMO_MAP");
		checkItem = demoMap[ct.c_uint(event.lport)]
		pseudoHash = event.lport + event.inum
		tag_16 = pseudoHash & 0xFFF
		print "tag value is %u", tag_16
		
		print "pseudo hash", pseudoHash
		dstMap[ct.c_uint16(tag_16)] = event
		#print dstMap[ct.c_uint(event.lport)]
		# check if bpf map is already pinned
		exist_fd = libbcc.lib.bpf_obj_get(ct.c_char_p("/sys/fs/bpf/trace"))
		print(exist_fd)
		print "event.comm", event.comm		
		if event.comm == "nginx":
			newPolicy = Policy()
			newPolicy.pid = event.pid
			newPolicy.dport = event.lport
			newPolicy.dstContext = "nginx"
			newPolicy.srcContext = "curl"
			policyMap[ct.c_long(event.lport)] = newPolicy
			#policyMap.__setitem__(ct.c_long(event.lport),newPolicy)
                elif event.comm == "curl":
                        newPolicy = Policy()
                        newPolicy.pid = event.pid
                        newPolicy.dport = event.lport
                        newPolicy.dstContext = "curl"  
                        newPolicy.srcContext = "nginx"
                        policyMap[ct.c_long(event.lport)] = newPolicy

#                        policyMap.__setitem__(ct.c_uint(event.lport),newPolicy)
			print "policy set"  
			print policyMap[ct.c_uint(event.lport)]
                elif event.comm == "java":
                        newPolicy = Policy()
                        newPolicy.pid = event.pid
                        newPolicy.dport = event.lport
                        newPolicy.dstContext = "java"  
                        newPolicy.srcContext = "nginx"  
                        policyMap[ct.c_long(event.lport)] = newPolicy

#                        policyMap.__setitem__(ct.c_uint(event.lport),newPolicy)
	
		if exist_fd < 0:
			ret = libbcc.lib.bpf_obj_pin(demoMap.map_fd, ct.c_char_p("/sys/fs/bpf/trace"))
			if ret != 0:
				raise Exception("Failed to pin map")

	

# this is where perf event collectioni is happening

def findNSpid(pid):
	# set file path
	filePath = '/proc/' +  str(pid) + '/status'
	print filePath
	with open(filePath) as procfile:
		for line in procfile:
			line1 = re.findall(r'NSpid', line)
			if line1:
				print line

dstMap = PinnedMap("/sys/fs/bpf/context", ct.c_uint16, Data, 1024)
policyMap = PinnedMap("/sys/fs/bpf/policy",ct.c_long, Policy, 1024)
b["events"].open_perf_buffer(handle_event)
while 1:
	b.kprobe_poll()
