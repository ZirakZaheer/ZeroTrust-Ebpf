sudo ip link del tap0
sudo ip link del ebpf_br
sudo ip netns delete vport_test2
sudo mount -t bpf none /sys/fs/bpf
sudo ip netns delete vport_test3
