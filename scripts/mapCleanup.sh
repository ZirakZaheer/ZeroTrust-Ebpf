sudo mount -t bpf none /sys/fs/bpf
sudo unlink /sys/fs/bpf/trace
sudo unlink /sys/fs/bpf/policy
sudo unlink /sys/fs/bpf/ifinum
sudo unlink /sys/fs/bpf/context
