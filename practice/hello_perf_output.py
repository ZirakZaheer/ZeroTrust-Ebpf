from bcc import BPF, libbcc
import ctypes as ct
import re
import os

prog = """
#include <linux/pid.h>
#include <linux/sched.h>
#include "bpf_elf.h"
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <net/net_namespace.h>
struct data_t {
 u32 pid;
 u64 cookie;
 char comm[TASK_COMM_LEN];
 struct net* targetNS;
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



BPF_PERF_OUTPUT(events);
BPF_TABLE_PUBLIC("hash", u32, struct data_t, DEMO_MAP, 1024);
int hello(struct pt_regs *ctx) {
	struct data_t data = {};
	struct task_struct *task;
	struct nsproxy* nsproxy;
	struct net* docker_ns;
	u64 sock_cookie = 0;
	data.pid = bpf_get_current_pid_tgid();
	//data.ts = bpf_ktime_get_ns();
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	task =  (struct task_struct*) bpf_get_current_task();
	sock_cookie = bpf_get_socket_cookie();
	data.cookie = sock_cookie;
	nsproxy = task->nsproxy;
	docker_ns = nsproxy->net_ns;
        
	data.targetNS = docker_ns;
	events.perf_submit(ctx, &data, sizeof(data));
	//	bpf_lookup_elem(DEMO_MAP, &data.pid, &data);
	u32 psNum = 1000;	
	DEMO_MAP.lookup_or_init(&psNum, &data);
	

	return 0;

}
"""
b = BPF(text=prog)
#b.attach_kprobe(event="sock_register", fn_name="hello")
#b.attach_kprobe(event="SyS_execve",fn_name="hello")
#b.attach_kprobe(event="sys_socketcall",fn_name="hello")
b.attach_kprobe(event="unix_socketpair",fn_name="hello")
TASK_COMM_LEN = 16

class Data(ct.Structure):
	_fields_ = [("pid", ct.c_ulonglong),
		    ("ts", ct.c_ulonglong),
		    ("comm", ct.c_char *  TASK_COMM_LEN)]
		   #  ("tagetNS",ct.Structure)]
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

start = 0

def print_event(cpu, data, size):
	global start
	event = ct.cast(data, ct.POINTER(Data)).contents
	if start == 0:
		start= event.ts
	time_s = (float(event.ts - start)) /10000000000
	if event.comm != "sshd":
		print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid,
        	"Hello, perf_output!"))
		print("calling function to find ns in pid")
#		print(event.targetNS)
		findNSpid(event.pid)	
		# make the map available clusterwide
		demoMap = b.get_table("DEMO_MAP");
		print("demoMap",demoMap.map_fd)
	#print(demoMap.items())
	
	# check if bpf map is already pinned
		exist_fd = libbcc.lib.bpf_obj_get(ct.c_char_p("/sys/fs/bpf/test"))
		print(exist_fd)
		if exist_fd < 0:
			ret = libbcc.lib.bpf_obj_pin(demoMap.map_fd, ct.c_char_p("/sys/fs/bpf/test"))
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
b["events"].open_perf_buffer(print_event)
while 1:
	b.kprobe_poll()
