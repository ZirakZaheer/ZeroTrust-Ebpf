/* 
 * Copyright (c) 2017 Nokia Bell Labs
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
//#include <unistd.h>
/* Module parameters */

static struct net *docker_ns;

module_param(docker_pid, int, 0);
MODULE_PARM_DESC(docker_pid, " Docker PID");

static int __init rtcp_init(void)
{
    int status;
    struct pid *target_pid;
    struct task_struct *task;
    status = 1;
    target_pid = find_vpid(docker_pid); //returns pid representation inside the docker container namespace
    if (!target_pid) {
        PERR("Cannot find PID %d\n", docker_pid);
        goto err_namespace;
    }

    task = pid_task(target_pid, PIDTYPE_PID);
    if (!task)  {
        PERR("Cannot find task for PID %d\n", docker_pid);
        goto err_namespace;
    }

    docker_ns = task->nsproxy->net_ns;
    PDEBUG("docker namespace for PID %d initialized %p\n",
           docker_pid, docker_ns);

    err_namespace:
    PERR("error happened\n");

    return status;
}

static void __exit rtcp_exit(void)
{

    PINFO("redundant tcp module exiting\n");
}



module_init(rtcp_init);
module_exit(rtcp_exit);

MODULE_AUTHOR("Nokia Bell Labs");
MODULE_DESCRIPTION("NS");
MODULE_LICENSE("GPL");

