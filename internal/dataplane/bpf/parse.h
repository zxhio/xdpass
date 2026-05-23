#ifndef XDPASS_PARSE_BPF_H
#define XDPASS_PARSE_BPF_H

#include "common.h"

static __always_inline void init_packet_ctx(struct xdp_md *ctx, struct packet_ctx *pkt)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	pkt->data = data;
	pkt->data_end = data_end;
	pkt->rx_queue_index = ctx->rx_queue_index;
	pkt->vlan_id = 0xffff;
}

static __always_inline int parse_l2(struct packet_ctx *pkt, __u16 *h_proto, __u64 *offset)
{
	struct ethhdr *eth = pkt->data;

	*offset = sizeof(*eth);
	if (!ptr_ok(eth, pkt->data_end, sizeof(*eth)))
		return -1;

	*h_proto = bpf_ntohs(eth->h_proto);
	if (*h_proto == ETH_P_8021Q || *h_proto == ETH_P_8021AD) {
		struct vlan_hdr {
			__be16 h_vlan_TCI;
			__be16 h_vlan_encapsulated_proto;
		};
		struct vlan_hdr *vlan = pkt->data + *offset;
		if (!ptr_ok(vlan, pkt->data_end, sizeof(*vlan)))
			return -1;
		pkt->vlan_id = bpf_ntohs(vlan->h_vlan_TCI) & 0x0fff;
		pkt->pkt_conds |= COND_VLAN;
		*h_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
		*offset += sizeof(*vlan);
	}

	return 0;
}

static __always_inline int parse_tcp(struct packet_ctx *pkt, __u64 offset)
{
	struct tcphdr *tcp = pkt->data + offset;

	if (!ptr_ok(tcp, pkt->data_end, sizeof(*tcp)))
		return -1;
	if (!ptr_ok(tcp, pkt->data_end, tcp->doff * 4))
		return -1;

	pkt->sport = bpf_ntohs(tcp->source);
	pkt->dport = bpf_ntohs(tcp->dest);
	pkt->pkt_conds |= COND_PROTO_TCP | COND_SRC_PORT | COND_DST_PORT;
	if (tcp->syn)
		pkt->pkt_conds |= COND_TCP_SYN;
	if (tcp->ack)
		pkt->pkt_conds |= COND_TCP_ACK;
	if (tcp->rst)
		pkt->pkt_conds |= COND_TCP_RST;
	if (tcp->fin)
		pkt->pkt_conds |= COND_TCP_FIN;
	if (tcp->psh)
		pkt->pkt_conds |= COND_TCP_PSH;

	return 0;
}

static __always_inline int parse_udp(struct packet_ctx *pkt, __u64 offset)
{
	struct udphdr *udp = pkt->data + offset;

	if (!ptr_ok(udp, pkt->data_end, sizeof(*udp)))
		return -1;

	pkt->sport = bpf_ntohs(udp->source);
	pkt->dport = bpf_ntohs(udp->dest);
	pkt->pkt_conds |= COND_PROTO_UDP | COND_SRC_PORT | COND_DST_PORT;

	return 0;
}

static __always_inline int parse_icmp(struct packet_ctx *pkt, __u64 offset)
{
	struct icmphdr *icmp = pkt->data + offset;

	if (!ptr_ok(icmp, pkt->data_end, sizeof(*icmp)))
		return -1;

	pkt->pkt_conds |= COND_PROTO_ICMP;
	if (icmp->type == ICMP_ECHO)
		pkt->pkt_conds |= COND_ICMP_ECHO_REQUEST;

	return 0;
}

static __always_inline int parse_ipv4(struct packet_ctx *pkt, __u64 offset)
{
	struct iphdr *ip = pkt->data + offset;

	if (!ptr_ok(ip, pkt->data_end, sizeof(*ip)))
		return -1;
	if (ip->ihl < 5)
		return -1;
	if (!ptr_ok(ip, pkt->data_end, ip->ihl * 4))
		return -1;

	pkt->sip = ip->saddr;
	pkt->dip = ip->daddr;
	pkt->ip_proto = ip->protocol;
	offset += ip->ihl * 4;

	switch (ip->protocol) {
	case IPPROTO_TCP:
		return parse_tcp(pkt, offset);
	case IPPROTO_UDP:
		return parse_udp(pkt, offset);
	case IPPROTO_ICMP:
		return parse_icmp(pkt, offset);
	default:
		return -1;
	}
}

static __always_inline int parse_arp(struct packet_ctx *pkt, __u64 offset)
{
	struct arphdr *arp = pkt->data + offset;

	if (!ptr_ok(arp, pkt->data_end, sizeof(*arp)))
		return -1;
	if (arp->ar_hln == 0 || arp->ar_pln == 0)
		return -1;

	__u64 arp_payload = 2 * (__u64)arp->ar_hln + 2 * (__u64)arp->ar_pln;
	if (!ptr_ok(arp, pkt->data_end, sizeof(*arp) + arp_payload))
		return -1;

	pkt->pkt_conds |= COND_PROTO_ARP;
	if (arp->ar_hrd == bpf_htons(ARPHRD_ETHER) && arp->ar_pro == bpf_htons(ETH_P_IP) &&
	    arp->ar_hln == ETH_ALEN && arp->ar_pln == 4) {
		if (!ptr_ok(arp, pkt->data_end, sizeof(*arp) + 2 * ETH_ALEN + 2 * sizeof(pkt->sip)))
			return -1;
		__builtin_memcpy(&pkt->sip, (void *)arp + sizeof(*arp) + ETH_ALEN, sizeof(pkt->sip));
		__builtin_memcpy(&pkt->dip,
				 (void *)arp + sizeof(*arp) + 2 * ETH_ALEN + sizeof(pkt->sip),
				 sizeof(pkt->dip));
	}
	if (bpf_ntohs(arp->ar_op) == ARPOP_REQUEST)
		pkt->pkt_conds |= COND_ARP_REQUEST;

	return 0;
}

static __always_inline int parse_packet(struct xdp_md *ctx, struct packet_ctx *pkt)
{
	__u64 offset = 0;
	__u16 h_proto = 0;

	init_packet_ctx(ctx, pkt);

	if (parse_l2(pkt, &h_proto, &offset) < 0)
		return -1;

	switch (h_proto) {
	case ETH_P_IP:
		return parse_ipv4(pkt, offset);
	case ETH_P_ARP:
		return parse_arp(pkt, offset);
	default:
		return -1;
	}
}

#endif
