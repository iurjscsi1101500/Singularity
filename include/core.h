#ifndef CORE_H
#define CORE_H

#define YOUR_SRV_IP "127.0.0.1"
#define YOUR_SRV_IPv6 { .s6_addr = { [15] = 1 } }

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched/signal.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/sysinfo.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/stat.h>
#include <linux/uio.h>
#include <linux/mount.h>
#include <linux/bpf.h>
#include <linux/fdtable.h>
#include <linux/spinlock.h>
#include <linux/ctype.h>
#include <linux/jiffies.h>
#include <linux/icmp.h>
#include <linux/inet.h>
#include <linux/umh.h>
#include <linux/workqueue.h>
#include <linux/tracepoint.h>
#endif
