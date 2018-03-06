pid1="$(sudo docker inspect -f '{{.State.Pid}}' "vport_test2")"
pid2="$(sudo docker inspect -f '{{.State.Pid}}' "vport_test3")"

sudo mkdir -p /var/run/netns
sudo ln -sf /proc/$pid1/ns/net "/var/run/netns/vport_test2"
sudo ln -sf /proc/$pid2/ns/net "/var/run/netns/vport_test3"
