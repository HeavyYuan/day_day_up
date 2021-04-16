#include <bcc/proto.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <net/inet_sock.h>
#include <linux/netfilter/x_tables.h>
#include <linux/virtio.h>
#include <linux/netdevice.h>




#ifdef TRACE_FILTER
TRACE_FILTER_DEFINE
#else
#define ADDR_FILTER 0
#define PORT_FILTER 0
#endif


#define MAX_FUNCNAME_LEN 64

struct ipv4_data_t {
     u32 pid;
     char func_name[MAX_FUNCNAME_LEN];
     u8 ip_version;
     u8  protocol;
     u64 saddr;
     u64 daddr;
     u16 sport;
     u16 dport;
     u32 stack_id;
 };

BPF_PERF_OUTPUT(ipv4_event_out);


enum{
    L1 = 1, /*driver layer*/
    L2,     /*ip layer*/
    L3      /*tcp layer*/
};

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
 {
     // unstable API. verify logic in tcp_hdr() -> skb_transport_header().
     return (struct tcphdr *)(skb->head + skb->transport_header);
 }
 
 static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
 {
     // unstable API. verify logic in ip_hdr() -> skb_network_header().
     return (struct iphdr *)(skb->head + skb->network_header);
 }

static int do_trace(struct pt_regs *ctx, const char *func_name, struct sock *sk, struct sk_buff *skb, int layer)
{

    struct ipv4_data_t  ipv4_event = {};
    u64 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;
    u8  protocol = 0;
    ipv4_event.pid = bpf_get_current_pid_tgid();
    ipv4_event.ip_version = 4;
    int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
    int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);
 
    __builtin_memcpy(&ipv4_event.func_name,func_name,MAX_FUNCNAME_LEN);
    if((layer == L2) || (layer == L3)){
    if (sk_lingertime_offset - gso_max_segs_offset == 4)
         // 4.10+ with little endian
 #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
         bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&sk->sk_gso_max_segs) - 3);
    else
         // pre-4.10 with little endian
         bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&sk->sk_wmem_queued) - 3);
 #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
         // 4.10+ with big endian
         bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&sk->sk_gso_max_segs) - 1);
    else
         // pre-4.10 with big endian
         bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&sk->sk_wmem_queued) - 1);
 #else
 # error "Fix your compiler's __BYTE_ORDER__?!"
 #endif
        saddr = sk->__sk_common.skc_rcv_saddr;
        daddr = sk->__sk_common.skc_daddr;
        sport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        sport = ntohs(sport);
        dport = ntohs(dport);
    }else if(layer == L1){
       struct tcphdr *tcp = skb_to_tcphdr(skb);
       struct iphdr *ip = skb_to_iphdr(skb);    
       rotocol = ip->protocol;
       bpf_probe_read_kernel(&ipv4_event.saddr, sizeof(ipv4_event.saddr), &(ip->saddr));
       saddr = ip->saddr;
       daddr = ip->daddr;
       sport = tcp->source;
       dport = tcp->dest;
       sport = ntohs(sport);
       dport = ntohs(dport);
    }else{
        return -1;
    }
    ipv4_event.sport = sport;
    ipv4_event.dport = dport;
    ipv4_event.saddr = saddr;
    ipv4_event.daddr = daddr;
    ipv4_event.protocol = protocol;   

    #if ADDR_FILTER 
    if (ipv4_event.ip_version == 4) {
        if (ADDR_FILTER != ipv4_event.saddr && ADDR_FILTER != ipv4_event.daddr)
            return -1;
    } else {
        return -1;
    }
    #endif
 
 
    #if PORT_FILTER
    if ( (ipv4_event.protocol == IPPROTO_UDP || ipv4_event.protocol == IPPROTO_TCP) &&
     (PORT_FILTER != ipv4_event.sport && PORT_FILTER != ipv4_event.port))
        return -1;
    #endif
    
    ipv4_event_out.perf_submit(ctx, &ipv4_event, sizeof(ipv4_event));
    return 0;
    
    
}


/*begin: TCP layer trace functions*/
int kprobe__tcp_sendmsg(struct pt_regs *ctx,struct sock *sk)
//int kprobe__tcp_sendmsg(struct pt_regs *ctx,struct sock *sk, struct msghdr *msg, size_t size)
{
    
    return do_trace(ctx, __func__+8, sk, NULL, L3);
    
}

int kprobe__tcp_write_xmit(struct pt_regs *ctx,struct sock *sk)
{
    return 0;
}


/* Build TCP header and checksum it. */
int kprobe____tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    return 0;
}

/*end: TCP layer trace functions*/


/*begin: IP layer trace functions*/

int kprobe____ip_queue_xmit(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
    return 0;
}

/*Returns 1 if the hook has allowed the packet to pass*/
/*different with kernel version(4.19.91-22.2.al7.x86_64 vs 3.10.0-693.11.6.el7)*/
int kprobe__ip_local_out(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return 0;
}

int kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return 0;
}

int kprobe__ip_finish_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return 0;
}

int kprobe__ip_finish_output2(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return 0;
}


/*end: IP layer trace functions*/

/*begin: driver layer trace functions*/

/*two code branches:
 * 1)dev_hard_start_xmit
 * 2) __dev_xmit_skb
 */
int kprobe__dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *sk)
{
    return 0;
}

/*send out directly*/
int kprobe__dev_hard_start_xmit(struct pt_regs *ctx, struct sk_buff *first, struct net_device *dev,struct netdev_queue *txq)
{
    return 0;
    //return do_trace(ctx, __func__+8, NULL,first, L1);
}

#if 0
/*traffic control, not available in bpf now*/
/*can't find __dev_xmit_skb in /sys/kernel/debug/tracing/available_filter_functions*/
int kprobe____dev_xmit_skb(struct pt_regs *ctx, struct sk_buff *skb, struct Qdisc *q,struct net_device *dev,struct netdev_queue *txq)
{
    return 0;
}
#endif

#if 0
/*branch 1) of dev_queue_xmit*/
/*can't find xmit_one in /sys/kernel/debug/tracing/available_filter_functions*/
int kprobe__xmit_one(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev,struct netdev_queue *txq)
{
    return 0;
}
#endif

/*virtio_net*/
int kprobe__start_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev)
{
    return 0;
    //return do_trace(ctx, __func__+8, NULL,skb, L1);
}

/*end: driver layer trace functions*/
