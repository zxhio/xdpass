#ifndef XDPASS_PARSE_BPF_H
#define XDPASS_PARSE_BPF_H

#include "common.h"

static __always_inline int parse_packet(struct xdp_md *ctx, struct packet_ctx *pkt)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u64 offset = sizeof(*eth);
	__u16 h_proto;

	pkt->data = data;
	pkt->data_end = data_end;
	pkt->rx_queue_index = ctx->rx_queue_index;
	pkt->vlan_id = 0xffff;

	if (!ptr_ok(eth, data_end, sizeof(*eth)))
		return -1;

	h_proto = bpf_ntohs(eth->h_proto);
	if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
		struct vlan_hdr {
			__be16 h_vlan_TCI;
			__be16 h_vlan_encapsulated_proto;
		};
		struct vlan_hdr *vlan = data + offset;
		if (!ptr_ok(vlan, data_end, sizeof(*vlan)))
			return -1;
		pkt->vlan_id = bpf_ntohs(vlan->h_vlan_TCI) & 0x0fff;
		pkt->pkt_conds |= COND_VLAN;
		h_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
		offset += sizeof(*vlan);
	}

	if (h_proto == ETH_P_IP) {
		struct iphdr *ip = data + offset;
		if (!ptr_ok(ip, data_end, sizeof(*ip)))
			return -1;
		if (ip->ihl < 5)
			return -1;
		if (!ptr_ok(ip, data_end, ip->ihl * 4))
			return -1;

		pkt->sip = ip->saddr;
		pkt->dip = ip->daddr;
		pkt->ip_proto = ip->protocol;
		offset += ip->ihl * 4;

		if (ip->protocol == XDPASS_IPPROTO_TCP) {
			struct tcphdr *tcp = data + offset;
			if (!ptr_ok(tcp, data_end, sizeof(*tcp)))
				return -1;
			if (!ptr_ok(tcp, data_end, tcp->doff * 4))
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

		if (ip->protocol == XDPASS_IPPROTO_UDP) {
			struct udphdr *udp = data + offset;
			if (!ptr_ok(udp, data_end, sizeof(*udp)))
				return -1;
			pkt->sport = bpf_ntohs(udp->source);
			pkt->dport = bpf_ntohs(udp->dest);
			pkt->pkt_conds |= COND_PROTO_UDP | COND_SRC_PORT | COND_DST_PORT;
			return 0;
		}

		if (ip->protocol == XDPASS_IPPROTO_ICMP) {
			struct icmphdr *icmp = data + offset;
			if (!ptr_ok(icmp, data_end, sizeof(*icmp)))
				return -1;
			pkt->pkt_conds |= COND_PROTO_ICMP;
			if (icmp->type == ICMP_ECHO)
				pkt->pkt_conds |= COND_ICMP_ECHO_REQUEST;
			return 0;
		}

		return -1;
	}

	if (h_proto == ETH_P_ARP) {
		struct arphdr *arp = data + offset;
		if (!ptr_ok(arp, data_end, sizeof(*arp)))
			return -1;
		if (arp->ar_hln == 0 || arp->ar_pln == 0)
			return -1;
		__u64 arp_payload = 2 * (__u64)arp->ar_hln + 2 * (__u64)arp->ar_pln;
		if (!ptr_ok(arp, data_end, sizeof(*arp) + arp_payload))
			return -1;
		pkt->pkt_conds |= COND_PROTO_ARP;
		if (arp->ar_hrd == bpf_htons(ARPHRD_ETHER) && arp->ar_pro == bpf_htons(ETH_P_IP) &&
		    arp->ar_hln == ETH_ALEN && arp->ar_pln == 4) {
			if (!ptr_ok(arp, data_end, sizeof(*arp) + 2 * ETH_ALEN + 2 * sizeof(pkt->sip)))
				return -1;
			__builtin_memcpy(&pkt->sip, (void *)arp + sizeof(*arp) + ETH_ALEN,
					 sizeof(pkt->sip));
			__builtin_memcpy(&pkt->dip,
					 (void *)arp + sizeof(*arp) + 2 * ETH_ALEN + sizeof(pkt->sip),
					 sizeof(pkt->dip));
		}
		if (bpf_ntohs(arp->ar_op) == ARPOP_REQUEST)
			pkt->pkt_conds |= COND_ARP_REQUEST;
		return 0;
	}

	return -1;
}

#endif
