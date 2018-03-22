sudo unlink /var/run/netns/vport_test2
sudo unlink /var/run/netns/vport_test3
#sudo unlink /sys/fs/bpf/trace
#sudo unlink /sys/fs/bpf/policy
sudo docker container kill vport_test2
sudo docker container kill vport_test3
sudo docker container rm vport_test2
sudo docker container rm vport_test3


sudo docker run -P -d --name=vport_test3 nginx
sudo docker run -P -d --user=0 --name=vport_test2 payara/server-full /bin/bash
pid1="$(sudo docker inspect -f '{{.State.Pid}}' "vport_test2")"
pid2="$(sudo docker inspect -f '{{.State.Pid}}' "vport_test3")"

sudo mkdir -p /var/run/netns
sudo ln -sf /proc/$pid1/ns/net "/var/run/netns/vport_test2"
sudo ln -sf /proc/$pid2/ns/net "/var/run/netns/vport_test3"
