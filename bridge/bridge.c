#include <bcc/proto.h>
#include <bcc/helpers.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/ns_common.h>
#include <net/net_namespace.h>
#include <linux/bpf.h>


//Total ports should be number of hosts attached + 1.
#define IP_TCP 6
#define IP_UDP 17
#define TOTAL_PORTS 3
#define TASK_COMM_LEN 16

struct mac_key {
  u64 mac;
};

struct data_t {
 u32 pid;
 u64 inum;
 u64 lport;
 char comm[TASK_COMM_LEN];
};

//contains integer alias too all the context attributes
struct context_t {
    u32 appName;
    u32 userName;
    //add attributes as needed
};

struct policy_t {
 u32 pid;
 u64 dport;
 char srcContext[TASK_COMM_LEN];
 char dstContext[TASK_COMM_LEN];
};

struct host_info {
  u32 ifindex;
  u64 rx_pkts;
  u64 tx_pkts;
};

BPF_TABLE("hash", struct mac_key, struct host_info, mac2host, 10240);
BPF_TABLE_PUBLIC("hash", u16, struct data_t, DEMO_MAP1, 1024);
BPF_TABLE_PUBLIC("hash", u64, struct policy_t, POLICY_MAP, 1024);
BPF_TABLE_PUBLIC("hash", u32, u64, if_inum, 1024);

struct config {
  int ifindex;
};


BPF_PERF_OUTPUT(skb_events);

BPF_TABLE("hash", int, struct config, conf, TOTAL_PORTS);
// Handle packets from (namespace outside) interface and forward it to bridge 
int handle_ingress(void *skb2) {
  //Lets assume that the packet is at 0th location of the memory.
  struct __sk_buff *skb = (struct __sk_buff *)skb2;
  u8 *cursor = 0;
  int tagPort = 1;
  u32 magic = 0xfaceb00c; //
  struct mac_key src_key = {};
  struct host_info src_info = {};
  
  //Extract ethernet header from the memory and point cursor to payload of ethernet header.
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  
  //assuming packets are IP_TCP
  struct ip_t  *ip = cursor_advance(cursor, sizeof(*ip));
  if (ip->nextp == IP_TCP) {
  	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
  	tagPort = tcp->src_port;
  } else if (ip->nextp == IP_UDP) {
	struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
	tagPort = udp->sport;
  }
 //we need sport and ifindex to locate the context from the context table
 u32 ifindex = skb->ifindex; 
 u64* inum = if_inum.lookup(&ifindex);
 // generate pseudohash
 u32 pseudoHash = 0;
 u16 tag_16 = 0;

// bpf_trace_printk("ifindex is %u \n", ifindex);
 if (inum) {
 	pseudoHash = *inum + tagPort;
	tag_16 = pseudoHash & 0xFFF;
 	bpf_trace_printk("inum is %u tagport is %d tag is %u \n",*inum, tagPort, tag_16);
 } else {
	bpf_trace_printk("inum not found\n");
	pseudoHash = tagPort;
 }

  //consult the identity table to fetch context
 //...
 if (tag_16 > 0) {
	//bpf_trace_printk("inum is %u pseudoHash is %d \n",inum, pseudoHash);
 	bpf_trace_printk("tag is %d,   %u \n", tag_16, ip->nextp);
 	struct data_t* d1 = DEMO_MAP1.lookup(&tag_16);
//	if (d1) bpf_trace_printk("data collected is %u,  %u, %u \n", d1->lport, d1->pid, d1->inum);
 }

// Extract bridge ifindex from the config file, that is populated by the python file while
  int zero = 0;
  struct config *cfg = conf.lookup(&zero);
  if (!cfg) return 1;
  src_key.mac = ethernet->src;
  src_info.ifindex = skb->ifindex;
  src_info.rx_pkts = 0;
  src_info.tx_pkts = 0;
   
  int cfg_index = 0;
  int vlan_proto = 0;
  u16  vlan_tci = tag_16; //tag information goes in here
  bpf_skb_vlan_push(skb, vlan_proto, vlan_tci); //pass this information from user space
  bpf_trace_printk("final tag inside packet is %u\n",  vlan_tci);
  bpf_trace_printk("                                   \n");
  bpf_trace_printk("                                   \n");    
  struct host_info *src_host = mac2host.lookup_or_init(&src_key, &src_info);
  lock_xadd(&src_host->rx_pkts, 1);
  bpf_clone_redirect(skb, cfg->ifindex, 1/*ingress*/);
  
  return 0;
}

// Handle packets inside the bridge and forward it to respective interface
int handle_egress(struct __sk_buff *skb) {
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  struct mac_key dst_key = {ethernet->dst};
  struct host_info *dst_host = mac2host.lookup(&dst_key);
  struct config *cfg = 0;
  u64 dstPort = 0;
  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

  if (ip->nextp == IP_TCP) {
        struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
        dstPort = tcp->dst_port;
  } else if (ip->nextp == IP_UDP) {
        struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
        dstPort = udp->dport;
  } else {
        dstPort = 1;
  }



  u16 packetTag = skb->vlan_tci;
  int vlan_proto = skb->vlan_proto;
  bpf_trace_printk("final tag taken from packet is %u\n",  skb->vlan_tci);
  
  //  pop the vlan header and send to the destination
  bpf_skb_vlan_pop(skb);
  bpf_trace_printk("final tag taken from packet is %u\n",  skb->vlan_tci);

  //lookup policy for destination process 
//  bpf_trace_printk("port to find policy against %u, %u \n",dstPort, ntohs(dstPort)); 
  struct policy_t* dstPolicy = POLICY_MAP.lookup(&dstPort);
  int policyFound  = 0;
  if (dstPolicy) { 
		policyFound = 1;
//		bpf_trace_printk("Policy for process is  ---  %d -- \n", dstPolicy->pid); 
  } else {
//                bpf_trace_printk("policy for process on port %u not found\n",dstPort);
  }

  int cfg_index = 0;
  //If flow exists then just send the packet to dst host else flood it to all ports.
  // enforce simple polixy based on pid carried in the packet
  struct data_t* context = DEMO_MAP1.lookup(&packetTag);
  if (!context) {
//	skb_events.perf_submit_skb(skb, skb->len, &packetTag, sizeof(packetTag));

	bpf_trace_printk("context not found, Tag inside packet is =  %u\n", packetTag);
	packetTag = 1;
	// go to end
  } else if (context)  bpf_trace_printk("Tag inside packet is =  %u, contextport is  = %u\n", packetTag, context->lport);
  
  if ((policyFound == 1) ||  (((ip->nextp != IP_TCP && ip->nextp != IP_UDP) && packetTag == 1))) {
	  
	  if (dst_host) {
		  bpf_clone_redirect(skb, dst_host->ifindex, 0/*ingress*/);
		  lock_xadd(&dst_host->tx_pkts, 1);
	  } else {
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
