from bcc import BPF
import ctypes as ct
import re
import os

prog = """

#include <linux/sched.h>


struct data_t {
 u32 pid;
 u64 ts;
 char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
	struct data_t data = {};

	data.pid = bpf_get_current_pid_tgid();
	data.ts = bpf_ktime_get_ns();
	bpf_get_current_comm(&data.comm, sizeof(data.comm));

	events.perf_submit(ctx, &data, sizeof(data));

	return 0;

}
"""
b = BPF(text=prog)
b.attach_kprobe(event="sys_socket", fn_name="hello")


TASK_COMM_LEN = 16

class Data(ct.Structure):
	_fields_ = [("pid", ct.c_ulonglong),
		    ("ts", ct.c_ulonglong),
		    ("comm", ct.c_char *  TASK_COMM_LEN)]

print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

start = 0

def print_event(cpu, data, size):
	global start
	event = ct.cast(data, ct.POINTER(Data)).contents
	if start == 0:
		start= event.ts
	time_s = (float(event.ts - start)) /10000000000
	print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid,
        "Hello, perf_output!"))
	print("calling function to find ns in pid")
	findNSpid(event.pid)
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
