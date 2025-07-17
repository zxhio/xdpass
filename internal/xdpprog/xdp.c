// +build ignore

#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct packet {
    // Protocol
    __be16 l2_proto;
    __be16 l3_proto;
    __be16 l4_proto;

    union {
        // IPv4
        struct {
            __be32 saddr;
            __be32 daddr;
        };

        // IPv6
        struct {
            struct in6_addr saddr6;
            struct in6_addr daddr6;
        };
    };

    // TCP/UDP
    __be16 sport;
    __be16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 128);
} xsk_map SEC(".maps");

// IP
struct ip_lpm_key {
    __u32 prefix_len;
    __u8 data[16];
};

struct ip_lpm_trie {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ip_lpm_key);
    __type(value, __u8);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
};

typedef enum {
    P_OK,
    P_ERR_L2_DATA_LEN,
    P_ERR_L3_DATA_LEN,
    P_ERR_L4_DATA_LEN,
    P_ERR_L3_UNSUPPORTED_PROTO,
    P_ERR_L4_UNSUPPORTED_PROTO,
    P_ERR_ARP_INVALID_HRD,
    P_ERR_ARP_INVALID_PRO,
    P_ERR_ARP_INVALID_HLEN,
    P_ERR_ARP_INVALID_PLEN,
    P_ERR_ARP_UNSUPPORTED_OP,
} p_err_t;

static p_err_t make_packet_icmp(struct packet *pkt, void *data, void *data_end);
static p_err_t make_packet_udp(struct packet *pkt, void *data, void *data_end);
static p_err_t make_packet_tcp(struct packet *pkt, void *data, void *data_end);
static p_err_t make_packet_ipv4(struct packet *pkt, void *data, void *data_end);
static p_err_t make_packet_ipv6(struct packet *pkt, void *data, void *data_end);
static p_err_t make_packet_arp(struct packet *pkt, void *data, void *data_end);
static p_err_t make_packet_vlan(struct packet *pkt, void *data, void *data_end);
static p_err_t make_packet(struct packet *pkt, void *data, void *data_end);

typedef __u8 BOOL;
#define TRUE 1
#define FALSE 0

static BOOL validate_packet(struct ip_lpm_trie *, const struct packet *pkt);
static BOOL validate_sip(struct ip_lpm_trie *, const struct packet *pkt);
static BOOL validate_dip(struct ip_lpm_trie *, const struct packet *pkt);

struct ip_lpm_trie redirect_lpm_trie SEC(".maps");
struct ip_lpm_trie pass_lpm_trie SEC(".maps");

SEC("xdp")
int xdp_redirect_xsk_prog(struct xdp_md *ctx)
{
    void *data = (void *)(__s64)ctx->data;
    void *data_end = (void *)(__s64)ctx->data_end;

    // Make packet
    struct packet pkt = {};
    if (make_packet(&pkt, data, data_end) != P_OK)
        return XDP_PASS; // Leave it to kernel

    // Pass check (whitelist)
    if (validate_packet(&pass_lpm_trie, &pkt) == TRUE)
        return XDP_PASS;

    // Redirect check
    if (validate_packet(&redirect_lpm_trie, &pkt) == TRUE) {
        int index = ctx->rx_queue_index;
        if (bpf_map_lookup_elem(&xsk_map, &index))
            return bpf_redirect_map(&xsk_map, index, XDP_DROP);
    }

    return XDP_DROP;
}

static BOOL validate_packet(struct ip_lpm_trie *trie, const struct packet *pkt)
{
    switch (pkt->l2_proto) {
    case ETH_P_802_3:
    case ETH_P_8021Q:
        return validate_sip(trie, pkt) || validate_dip(trie, pkt);
    default:
        return FALSE;
    }
}

static BOOL validate_sip(struct ip_lpm_trie *trie, const struct packet *pkt)
{
    struct ip_lpm_key key = {};
    switch (pkt->l3_proto) {
    case ETH_P_ARP:
    case ETH_P_IP:
        key.prefix_len = 32;
        __builtin_memcpy(key.data, &(pkt->saddr), sizeof(pkt->saddr));
        break;
    case ETH_P_IPV6:
        key.prefix_len = 128;
        __builtin_memcpy(key.data, &(pkt->saddr6), sizeof(pkt->saddr6));
        break;
    default:
        return FALSE;
    }
    return bpf_map_lookup_elem(trie, &key) ? TRUE : FALSE;
}

static BOOL validate_dip(struct ip_lpm_trie *trie, const struct packet *pkt)
{
    struct ip_lpm_key key = {};
    switch (pkt->l3_proto) {
    case ETH_P_ARP:
    case ETH_P_IP:
        key.prefix_len = 32;
        __builtin_memcpy(key.data, &(pkt->daddr), sizeof(pkt->daddr));
        break;
    case ETH_P_IPV6:
        key.prefix_len = 128;
        __builtin_memcpy(key.data, &(pkt->daddr6), sizeof(pkt->daddr6));
        break;
    default:
        return FALSE;
    }
    return bpf_map_lookup_elem(trie, &key) ? TRUE : FALSE;
}

static p_err_t make_packet(struct packet *pkt, void *data, void *data_end)
{
    // L2
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return P_ERR_L2_DATA_LEN;

    pkt->l2_proto = ETH_P_802_3;

    __be16 eth_type = bpf_ntohs(eth->h_proto);
    __be16 off = sizeof(*eth);
    switch (eth_type) {
    case ETH_P_8021Q:
        return make_packet_vlan(pkt, data + off, data_end);
    case ETH_P_ARP:
        return make_packet_arp(pkt, data + off, data_end);
    case ETH_P_IP:
        return make_packet_ipv4(pkt, data + off, data_end);
    case ETH_P_IPV6:
        return make_packet_ipv6(pkt, data + off, data_end);
    default:
        return P_ERR_L3_UNSUPPORTED_PROTO;
    }
}

struct arphdr_eth {
    __u8 ar_sha[ETH_ALEN];
    __u8 ar_sip[4];
    __u8 ar_tha[ETH_ALEN];
    __u8 ar_tip[4];
};

static p_err_t make_packet_arp(struct packet *pkt, void *data, void *data_end)
{
    struct arphdr *arp = (struct arphdr *)data;
    if ((void *)(arp + 1) > data_end)
        return P_ERR_L2_DATA_LEN;

    // sizeof(*arp) == 8
    struct arphdr_eth *arp_eth = (struct arphdr_eth *)(data + 8);
    if ((void *)(arp_eth + 1) > data_end)
        return P_ERR_L2_DATA_LEN;

    if (arp->ar_hrd != bpf_htons(ARPHRD_ETHER))
        return P_ERR_ARP_INVALID_HRD;
    if (arp->ar_hln != ETH_ALEN)
        return P_ERR_ARP_INVALID_HLEN;

    // IPv4
    if (arp->ar_pro != bpf_htons(ETH_P_IP))
        return P_ERR_ARP_INVALID_PRO;
    if (arp->ar_pln != 4)
        return P_ERR_ARP_INVALID_PLEN;

    pkt->saddr = pkt->l3_proto = ETH_P_ARP;
    __builtin_memcpy(&pkt->saddr, arp_eth->ar_sip, sizeof(pkt->saddr));
    __builtin_memcpy(&pkt->daddr, arp_eth->ar_tip, sizeof(pkt->saddr));

    return P_OK;
}

static p_err_t make_packet_vlan(struct packet *pkt, void *data, void *data_end)
{
    struct vlan_hdr *vlan = (struct vlan_hdr *)data;
    if ((void *)(vlan + 1) > data_end)
        return P_ERR_L2_DATA_LEN;

    pkt->l2_proto = ETH_P_8021Q;

    __be16 off = sizeof(*vlan);
    switch (bpf_ntohs(vlan->h_vlan_encapsulated_proto)) {
    case ETH_P_ARP:
        return make_packet_arp(pkt, data + off, data_end);
    case ETH_P_IP:
        return make_packet_ipv4(pkt, data + off, data_end);
    case ETH_P_IPV6:
        return make_packet_ipv6(pkt, data + off, data_end);
    default:
        return P_ERR_L3_UNSUPPORTED_PROTO;
    }
}

static p_err_t make_packet_ipv4(struct packet *pkt, void *data, void *data_end)
{
    struct iphdr *ip = (struct iphdr *)data;
    if ((void *)(ip + 1) > data_end)
        return P_ERR_L3_DATA_LEN;

    pkt->l3_proto = ETH_P_IP;
    pkt->saddr = ip->saddr;
    pkt->daddr = ip->daddr;

    __u16 off = ip->ihl * 4;
    switch (ip->protocol) {
    case IPPROTO_ICMP:
        return make_packet_icmp(pkt, data + off, data_end);
    case IPPROTO_UDP:
        return make_packet_udp(pkt, data + off, data_end);
    case IPPROTO_TCP:
        return make_packet_tcp(pkt, data + off, data_end);
    default:
        return P_ERR_L4_UNSUPPORTED_PROTO;
    }
}

static p_err_t make_packet_ipv6(struct packet *pkt, void *data, void *data_end)
{
    struct ipv6hdr *ip = (struct ipv6hdr *)data;
    if ((void *)(ip + 1) > data_end)
        return P_ERR_L3_DATA_LEN;

    pkt->l3_proto = ETH_P_IPV6;
    pkt->saddr6 = ip->saddr;
    pkt->daddr6 = ip->daddr;

    __u16 off = sizeof(*ip);
    switch (ip->nexthdr) {
    case IPPROTO_ICMP:
        return make_packet_icmp(pkt, data + off, data_end);
    case IPPROTO_UDP:
        return make_packet_udp(pkt, data + off, data_end);
    case IPPROTO_TCP:
        return make_packet_tcp(pkt, data + off, data_end);
    default:
        return P_ERR_L4_UNSUPPORTED_PROTO;
    }
}

static p_err_t make_packet_icmp(struct packet *pkt, void *data, void *data_end)
{
    struct icmphdr *icmp = (struct icmphdr *)data;
    if ((void *)(icmp + 1) > data_end)
        return P_ERR_L4_DATA_LEN;

    pkt->l4_proto = IPPROTO_ICMP;
    pkt->sport = 0;
    pkt->dport = 0;

    return P_OK;
}

static p_err_t make_packet_udp(struct packet *pkt, void *data, void *data_end)
{
    struct udphdr *udp = (struct udphdr *)data;
    if ((void *)(udp + 1) > data_end)
        return P_ERR_L4_DATA_LEN;

    pkt->l4_proto = IPPROTO_UDP;
    pkt->sport = bpf_ntohs(udp->source);
    pkt->dport = bpf_ntohs(udp->dest);

    return P_OK;
}

static p_err_t make_packet_tcp(struct packet *pkt, void *data, void *data_end)
{
    struct tcphdr *tcp = (struct tcphdr *)data;
    if ((void *)(tcp + 1) > data_end)
        return P_ERR_L4_DATA_LEN;

    pkt->l4_proto = IPPROTO_TCP;
    pkt->sport = bpf_ntohs(tcp->source);
    pkt->dport = bpf_ntohs(tcp->dest);

    return P_OK;
}

char _license[] SEC("license") = "GPL";
