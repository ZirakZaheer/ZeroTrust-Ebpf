

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
#include "extractModule.h"
#include <linux/kprobes.h>
#include <net/inet_sock.h>
#include <
#include <asm/atomic64_64.h>
//#include <unistd.h>
/* Module parameters */
#define pr_fmt(fmt) "ETN JPROBE: %s:%d: " fmt, __FUNCTION__, __LINE__
//static struct net *docker_ns;
//static int docker_pid = 11608;

//module_param(docker_pid, int, 0);
//MODULE_PARM_DESC(docker_pid, " Docker PID");


static int trace_sock_graft(struct sock *sk, struct socket *parent)
{
        printk("jprobe successful in entering the inet_listen\n");
        if (sk == NULL){
                printk("sock1 is Null");
        }
        if (parent == NULL) {
                printk("sock2 is Null");
        }
	
        if (sk) {
                        atomic64_cmpxchg(&sk->sk_cookie, 0, 1234);
              
                        pr_info("sk_mark is currently %d\n", sk->sk_mark);
                        sk->sk_mark = 1234;
                        pr_info("sk_mark changed to %d\n", sk->sk_mark);
			struct inet_sock *netSk = inet_sk(sk);
			if (netSk){
				if (netSk->inet_sport) {
					pr_info("sk port %d\n", netSk->inet_sport); 
				}
			}
			
		// sk is assigned to the parent sock in sock_graft, so rechecking if sk_mark is still			//the same 
		if (parent){
			if (parent->sk) {
				pr_info("parent_mark %d\n", parent->sk->sk_mark);
			}
		}
       }
        jprobe_return();
        return 0;
}


static struct jprobe inet_listen_jprobe = {
        .entry                  = trace_sock_graft,
        .kp = {
                .symbol_name    = "security_sock_graft",
        },
};

static int __init jprobe_init(void)
{
        int ret;

        ret = register_jprobe(&inet_listen_jprobe);
        if (ret < 0) {
                pr_err(KERN_INFO "register_jprobe failed, returned %d\n", ret);
                return -1;
        }
        pr_info("Planted jprobe at %p, handler addr %p\n",
               inet_listen_jprobe.kp.addr, inet_listen_jprobe.entry);
        return 0;
}

static void __exit jprobe_exit(void)
{
        unregister_jprobe(&inet_listen_jprobe);
        pr_info("jprobe at %p unregistered\n", inet_listen_jprobe.kp.addr);
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");

