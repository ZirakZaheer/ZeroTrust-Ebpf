/*
 *Copyright (c) 2017 Nokia Bell Labs
 *
 */

#ifndef __EXTRACTMODULE_H__
#define __EXTRACTMODULE_H__

#include <linux/proc_fs.h>

//extern struct proc_dir_entry *proc_net_rtcp;

#ifdef DEBUG
#define PDEBUG(fmt, args...) printk(KERN_DEBUG "RTCP: " fmt, ## args)
#else
#define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

#define PINFO(fmt, args...) printk(KERN_INFO "RTCP: " fmt, ## args)
#define PERR(fmt, args...) printk(KERN_ERR "RTCP: " fmt, ## args)

#endif
