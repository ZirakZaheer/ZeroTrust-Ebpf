from bcc import BPF


BPF(text='int kbrobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0;}').trace_print()
