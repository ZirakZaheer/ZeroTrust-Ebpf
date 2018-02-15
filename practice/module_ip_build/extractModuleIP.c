

/*Copyright (c) 2017 Nokia Bell Labs
 * Written for Ubuntu 16.04 (4.4.0-83-generic)
 *
 */
#include <linux/netlink.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inetdevice.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/arp.h>
#include <net/net_namespace.h>
#include "extractModuleIP.h"
#include <linux/kprobes.h>
#include <net/inet_sock.h>

//#include <unistd.h>
/* Module parameters */
#define pr_fmt(fmt) "ETN JPROBE: %s:%d: " fmt, __FUNCTION__, __LINE__
//static struct net *docker_ns;
//static int docker_pid = 11608;

//module_param(docker_pid, int, 0);
//MODULE_PARM_DESC(docker_pid, " Docker PID");


static int trace_ip_build( struct socket *sock, struct msghdr *msg, size_t size)
//static int trace_ip_build(struct sk_buff *skb)
//static int trace_ip_build(struct sk_buff *skb, struct net_device *dev,
//					    struct netdev_queue *txq, bool more)
{
        //printk("jprobe successful in entering the trace_ip_build\n");
        struct sock * sk = sock->sk;
	if (sk == NULL){
                printk("sock1 is Null");
        }
//        if (skb == NULL) {
//                printk("skb is Null");
//        }

        if (sk) {
		struct inet_sock *netSk = inet_sk(sk);
		if (netSk)
		   if (netSk->inet_sport != 5632) {              
                        pr_info("sk_mark is currently %d\n", sk->sk_mark);
                        sk->sk_mark = 1234;
                        pr_info("sk_mark changed to %d\n", sk->sk_mark);
			struct inet_sock *netSk = inet_sk(sk);
			if (netSk){
			//	if (netSk->inet_sport) {
					pr_info("sk port %d\n", netSk->inet_sport); 
			//	}
			}
			}
		}
		// sk is assigned to the parent sock in sock_graft, so rechecking if sk_mark is still			//the same 
	//	if (skb){
	//		if (skb->mark) {
	//			pr_info("skb_mark %d\n", skb->mark);
	//}
		
       
        jprobe_return();
        return 0;
}


static struct jprobe ip_build_jprobe = {
        .entry                  = trace_ip_build,
        .kp = {
                .symbol_name    = "inet_sendmsg",
        },
};

static int __init jprobe_init(void)
{
        int ret;

        ret = register_jprobe(&ip_build_jprobe);
        if (ret < 0) {
                pr_err(KERN_INFO "register_jprobe failed, returned %d\n", ret);
                return -1;
        }
        pr_info("Planted jprobe at %p, handler addr %p\n",
               ip_build_jprobe.kp.addr, ip_build_jprobe.entry);
        return 0;
}

static void __exit jprobe_exit(void)
{
        unregister_jprobe(&ip_build_jprobe);
        pr_info("jprobe at %p unregistered\n", ip_build_jprobe.kp.addr);
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");

