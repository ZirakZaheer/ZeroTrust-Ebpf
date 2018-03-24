#include <bcc/proto.h>
#include <bcc/helpers.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/ns_common.h>
#include <net/net_namespace.h>
#include <linux/bpf.h>
#include <linux/string.h>

//Total ports should be number of hosts attached + 1.
#define IP_TCP 6
#define IP_UDP 17
#define TOTAL_PORTS 3
#define TASK_COMM_LEN 16
#define TAG_MASK 0xFFF
struct mac_key {
  u64 mac;
};

struct context_t {
 char appName[TASK_COMM_LEN];
 // context grows here
};

//contains integer alias too all the context attributes
struct context_not_t {
    u32 appName;
    u32 userName;
    //add attributes as needed
};

struct policy_t {
 char srcContext[TASK_COMM_LEN];
 char dstContext[TASK_COMM_LEN];
 u32 action;
};

struct host_info {
  u32 ifindex;
  u64 rx_pkts;
  u64 tx_pkts;
};

struct config {
  int ifindex;
};

BPF_TABLE("hash", struct mac_key, struct host_info, mac2host, 10240);
BPF_TABLE_PUBLIC("hash", u16, struct context_t, DEMO_MAP1, 1024);
BPF_TABLE_PUBLIC("hash", u64, struct policy_t, POLICY_MAP, 1024);
BPF_TABLE_PUBLIC("hash", u32, u64, if_inum, 1024);
BPF_TABLE("hash", int, struct config, conf, TOTAL_PORTS);
BPF_PERF_OUTPUT(skb_events);

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
 if (tag_16 > 0) {
 	bpf_trace_printk("tag is %d,   %u \n", tag_16, ip->nextp);
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
/*
static inline void copyStr(char dst[], char src[]) {
	for (int i = 0; i < sizeof(src) -1;i++) {
        	dst[i] = src[i];
  	}
}
*/
static inline int policyCheck(struct context_t* src, struct context_t* dst) {
	/* access to policy maps, looks up policy tables by combining the carried context */
	
  /* return policy decision */
  /* to lookup first from the tag */
  /* this function will expand and functionality would need to adapt when PTM are introduced*/
/*  if ((!src) || (!dst)) return -1; */
  int srcVal = 0;
	for (int i = 0; i < sizeof(src->appName)-1; i++) {
			srcVal += (int) src->appName[i];
	}
  int dstVal = 0;
	for (int i = 0; i < sizeof(dst->appName)-1; i++) {
      dstVal += (int) dst->appName[i];
  }
  int finalTag = srcVal + dstVal;
  
  
  return finalTag;
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

  /* tag for destination container */
 
  u64* inum = 0;
  if (dst_host) {
      u32 ifindex = dst_host->ifindex;
      inum = if_inum.lookup(&ifindex);
  } else {
      bpf_trace_printk("destination host entry missing inside map\n");
  }
  u32 pseudoHash = 0;
  u16 receiver_tag_16 = 123;
  u16 packetTag = skb->vlan_tci;
  if (inum) {
        pseudoHash = *inum + dstPort;
        receiver_tag_16 = pseudoHash & TAG_MASK;
  } else {
        // throw error
        bpf_trace_printk("inum not found\n");
  }

  /*  todo: fetch receiveing container context */
//  struct context_t recv = {};
  //struct context_t* recv_context = 0;
//  if (receiver_tag_16) {
//       struct context_t* recv_context = DEMO_MAP1.lookup(&packetTag);
/*        if (recv_context) {
	//bpf_probe_read(&recv.appName[0], sizeof(char),&recv_context->appName[0]);
  		for (int i = 0; i < sizeof(recv_context->appName) -1;i++) {
        		recv.appName[i] = recv_context->appName[i];
  		}	
  	}
*/	
//  } else {
//       bpf_trace_printk("receiver tag missing, how come?\n");
//  }
/*  if (recv_context) {
       bpf_trace_printk("receiver context found\n");
  } else {
	//guaranteed to be found
  }
*/
  /* tag for sending container */

  /*todo: fetch sending container context*/
//  struct context_t* recv_context = DEMO_MAP1.lookup(&packetTag);
//  struct context_t* sender_context = DEMO_MAP1.lookup(&packetTag);

//  if (sender_context) { 
//       bpf_trace_printk("sender context found\n");
//  }

/* else {
 //   todo slow path
 //    add logic to handle abnormal packets 
   //skb_events.perf_submit_skb(skb, skb->len, &packetTag, sizeof(packetTag));
  }
*/
  /*todo: key formation for policy table lookup: will need to include set/subset of recv&send context */
  // static inline function that forms a key by combining recv and sender context, also takes in Policy Templates for key formation currently I can ignore this sincle context is simple
  /* key should be same as the policy key in userspace*/
//  struct context_t src = {};
  u32 num = 0;
  u32 othernum = 45;
  char testapp[10] = "heylo";
  //src.appName[0] = sender_context->appName[0];
//  copyStr(src.appName, sender_context->appName); 
//  copyStr(recv.appName, recv_context->appName);
//  if (sender_context) { 
//	bpf_probe_read_str(&src.appName, sizeof(sender_context->appName), &sender_context->appName);
        //src.appName = sender_context->appName;
         
//  for (int i = 0; i < sizeof(sender_context->appName) -1;i++) {
//	src.appName[i] = sender_context->appName[i];
//  }

  /*
  if (src)
  	bpf_trace_printk("sender context %s \n", src.appName);
  if (recv)
  	bpf_trace_printk("receiver context %s \n", recv.appName);
  */




//  	int keyFormed = policyCheck(&src, &recv);
//  	bpf_trace_printk("keyformation check %d \n", keyFormed);
//  }
  /*remove vlan header from skb */
  bpf_skb_vlan_pop(skb);

  /*handle policy here*/
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
  struct context_t* context = DEMO_MAP1.lookup(&packetTag);
  if (!context) {
//	skb_events.perf_submit_skb(skb, skb->len, &packetTag, sizeof(packetTag));

	bpf_trace_printk("context not found, Tag inside packet is =  %u\n", packetTag);
	packetTag = 1;
	// go to end
  } else if (context)  bpf_trace_printk("Tag inside packet is =  %u, context is  = \n", packetTag);
  
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
