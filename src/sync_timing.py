from bcc import BPF

b = BPF(text="""

#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(last);
//BPF_HASH(count);
int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;
    u64 keyc  = 0;
    tsp = last.lookup(&key);
    if (tsp != 0) {
	delta = bpf_ktime_get_ns() - *tsp;
	if (delta < 1000000000) {
		bpf_trace_printk("%d\\n", delta / 1000000);
	}
	last.delete(&key);
    }
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
""")

b.attach_kprobe(event="sys_sync", fn_name="do_trace")


# formating output received from pipe

start = 0
while 1:
	(task, pid, cpu, flags, ts, ms) = b.trace_fields()
	if start == 0:
		start = ts
	ts = ts - start
	countable = b.get_table("count")
	print("At time %.2f s: multiple synce detected, last %s ms ago and the count is  %d" % (ts, ms,countable[0]))




