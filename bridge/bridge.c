// Copyright (c) PLUMgrid, Inc. // Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/ns_common.h>
#include <net/net_namespace.h>
#include <linux/bpf.h>
//Total ports should be number of hosts attached + 1.
#define TOTAL_PORTS 3
#define TASK_COMM_LEN 16
//#include "/usr/include/stdio.h"
//#include "bcc/src/cc/libbpf.h"
//#include </usr/include/stdlib.h>
//#include <stdint.h>
//#include <cstdio>
//#include<string.h>

/*
static inline
struct net *sock_net(const struct sock *sk)
{
	return read_pnet(&sk->sk_net);
}


*/


struct mac_key {
  u64 mac;
};

struct data_t {
 u32 pid;
 u64 ts;
 char comm[TASK_COMM_LEN];
};


struct host_info {
  u32 ifindex;
  u64 rx_pkts;
  u64 tx_pkts;
};

BPF_TABLE("hash", struct mac_key, struct host_info, mac2host, 10240);
BPF_TABLE("hash", u32, struct data_t, POLICY_MAP, 1024);
struct config {
  int ifindex;
};


//BPF_PERF_OUTPUT(vlanevents);
BPF_TABLE("hash", int, struct config, conf, TOTAL_PORTS);
BPF_HASH(DEMO_MAP1, u32, struct data_t, 1024);
// Handle packets from (namespace outside) interface and forward it to bridge 
int handle_ingress(struct __sk_buff *skb) {
  //Lets assume that the packet is at 0th location of the memory.
  u8 *cursor = 0;
  struct mac_key src_key = {};
  struct host_info src_info = {};
  //Extract ethernet header from the memory and point cursor to payload of ethernet header.
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  // Extract bridge ifindex from the config file, that is populated by the python file while
  // creating the bridge.
  int zero = 0;
  struct config *cfg = conf.lookup(&zero);
  if (!cfg) return 1;
  src_key.mac = ethernet->src;
  src_info.ifindex = skb->ifindex;
  src_info.rx_pkts = 0;
  src_info.tx_pkts = 0;

  int cfg_index = 0;
  int vlan_proto = 0;
  int vlan_tci = 12; //tag information goes in here
  bpf_skb_vlan_push(skb, vlan_proto, vlan_tci); //pass this information from user space
    
  struct host_info *src_host = mac2host.lookup_or_init(&src_key, &src_info);
  lock_xadd(&src_host->rx_pkts, 1);
  bpf_clone_redirect(skb, cfg->ifindex, 1/*ingress*/);
  //bpf_trace_printk("[egress] sending traffic to ifindex=%d\n, pkt_type=%d", cfg->ifindex, ethernet->type);
  

//  bpf_get_socket_cookie(skb);
// Test if demo map is working correctly
  u32 testInd = vlan_tci;
  struct data_t dummyData = {};
  dummyData.pid = vlan_tci;
  dummyData.ts = ts;
  strcpy(&dummyData.comm,"testcode");
  struct data_t* testData = DEMO_MAP1.lookup_or_init(&testInd,&dummyData);
  //access demo map
  int ret = 0;
//  int fd = bpf_obj_get(testString);
//  printf("testing map: fd%d, vlan_tci: %d\n", fd, vlan_tci);
//  if (fd > 0) {
//      ret  =	bpf_map_update_elem(&fd, &vlan_tci, &dummyData, 0);
//       if (ret == 0){
//	printf("success\n");
//	}
//  }

//  if (testData != NULL)
  //	bpf_trace_printk("data = %d\n",  testData->pid);
  return 0;
}

// Handle packets inside the bridge and forward it to respective interface
int handle_egress(struct __sk_buff *skb) {
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  struct mac_key dst_key = {ethernet->dst};
  struct host_info *dst_host = mac2host.lookup(&dst_key);
  struct config *cfg = 0;
  struct net * contNet;
  u32 cont_inum = 0;
  u32 vlan_tci = skb->vlan_tci;
  int vlan_proto = skb->vlan_proto;
//  pop the vlan header and send to the destination
  bpf_skb_vlan_pop(skb);
// extract struct net from skb, to getnamespace struct and inum
    //contNet = sock_net(skb->sk);
    //cont_inum = contNet->ns.inum;

  int cfg_index = 0;
  //If flow exists then just send the packet to dst host else flood it to all ports.
  // enforce simple polixy based on pid carried in the packet
  if (vlan_tci == 12) {
	  if (dst_host) {

		  bpf_clone_redirect(skb, dst_host->ifindex, 0/*ingress*/);
		  lock_xadd(&dst_host->tx_pkts, 1);
	  } else {
		  //if (ethernet->type != 0x0800) return 0;

		  for ( int j=1;j<TOTAL_PORTS;j++ )
		  {
			  cfg_index = j;
			  cfg = conf.lookup(&cfg_index);
			  if (cfg) {
				  bpf_clone_redirect(skb, cfg->ifindex, 0);//egress);
			  }
		  }

	  }
 } else {
          // drop packets
 }

  return 0;
}
