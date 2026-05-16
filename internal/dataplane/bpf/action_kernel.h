#ifndef XDPASS_ACTION_KERNEL_BPF_H
#define XDPASS_ACTION_KERNEL_BPF_H

#include "action_event.h"
#include "action_verdict.h"

#define TCPHDR_LEN      20
#define IPHDR_LEN       20
#define RST_ACK_FLAGS   0x14
#define TCP_DOFF_5      0x50
#define DEFAULT_TTL     64

static __always_inline __u16 csum_fold(__u32 sum)
{
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (__u16)~sum;
}

static __always_inline int apply_tcp_reset(struct xdp_md *ctx, const struct packet_ctx *pkt,
					   const struct rule_meta *rule)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u16 h_proto;
	__u64 offset;
	struct iphdr *ip;
	struct tcphdr *tcp;
	__u8 smac[6], dmac[6];
	__be32 tmp_ip;
	__be16 tmp_port;
	__u32 csum;
	const __u16 *p;

	if (!ptr_ok(eth, data_end, sizeof(*eth)))
		goto fail;

	/* Swap Ethernet MAC addresses. */
	__builtin_memcpy(smac, eth->h_source, 6);
	__builtin_memcpy(dmac, eth->h_dest, 6);
	__builtin_memcpy(eth->h_dest, smac, 6);
	__builtin_memcpy(eth->h_source, dmac, 6);

	/* Skip VLAN tag if present. */
	h_proto = bpf_ntohs(eth->h_proto);
	offset = sizeof(*eth);
	if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
		struct vlan_hdr {
			__be16 h_vlan_TCI;
			__be16 h_vlan_encapsulated_proto;
		};
		struct vlan_hdr *vlan = data + offset;
		if (!ptr_ok(vlan, data_end, sizeof(*vlan)))
			goto fail;
		h_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
		offset += sizeof(*vlan);
	}

	if (h_proto != ETH_P_IP)
		goto fail;

	/* Verify IPv4 header access. */
	ip = data + offset;
	if (!ptr_ok(ip, data_end, sizeof(*ip)))
		goto fail;
	if (ip->ihl < 5)
		goto fail;
	if (!ptr_ok(ip, data_end, ip->ihl * 4))
		goto fail;
	offset += ip->ihl * 4;

	/* Verify TCP header access. */
	tcp = data + offset;
	if (!ptr_ok(tcp, data_end, sizeof(*tcp)))
		goto fail;

	/* Swap IP addresses. */
	tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;

	/* Swap TCP ports. */
	tmp_port = tcp->source;
	tcp->source = tcp->dest;
	tcp->dest = tmp_port;

	/* Set ACK number: original seq + 1 if ACK was set. */
	if (tcp->ack)
		tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);
	else
		tcp->ack_seq = 0;

	/* Clear sequence number, checksum, urgent pointer. */
	tcp->seq = 0;
	tcp->check = 0;
	tcp->urg_ptr = 0;

	/* Set data offset = 5 (20 bytes), flags = RST | ACK. */
	*((__u8 *)tcp + 12) = TCP_DOFF_5;
	*((__u8 *)tcp + 13) = RST_ACK_FLAGS;

	/* Update IPv4 header. */
	ip->tot_len = bpf_htons(IPHDR_LEN + TCPHDR_LEN);
	ip->ttl = DEFAULT_TTL;
	ip->check = 0;
	ip->ihl = IPHDR_LEN / 4;

	/* IPv4 checksum: unrolled over the 20-byte header. */
	p = (const __u16 *)ip;
	csum = p[0] + p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7] + p[8] + p[9];
	ip->check = csum_fold(csum);

	/* TCP checksum: pseudo-header + unrolled 20-byte TCP header. */
	csum = (__u16)(ip->saddr >> 16) + (__u16)(ip->saddr & 0xffff);
	csum += (__u16)(ip->daddr >> 16) + (__u16)(ip->daddr & 0xffff);
	csum += bpf_htons(XDPASS_IPPROTO_TCP);
	csum += bpf_htons(TCPHDR_LEN);
	p = (const __u16 *)tcp;
	csum += p[0] + p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7] + p[8] + p[9];
	tcp->check = csum_fold(csum);

	stats_inc(STAT_KERNEL_RESPONSE_PACKETS);
	stats_inc(STAT_KERNEL_RESPONSE_XDP_TX_PACKETS);
	emit_rule_event(pkt, rule, VERDICT_TX);
	return XDP_TX;

fail:
	stats_inc(STAT_KERNEL_RESPONSE_PACKETS);
	stats_inc(STAT_KERNEL_RESPONSE_ERROR_PACKETS);
	emit_rule_event(pkt, rule, VERDICT_TX);
	return response_failure_verdict();
}

static __always_inline int apply_kernel_response(struct xdp_md *ctx, const struct packet_ctx *pkt,
						 const struct rule_meta *rule)
{
	if (rule->action == ACTION_TCP_RESET)
		return apply_tcp_reset(ctx, pkt, rule);

	stats_inc(STAT_KERNEL_RESPONSE_PACKETS);
	stats_inc(STAT_KERNEL_RESPONSE_ERROR_PACKETS);
	emit_rule_event(pkt, rule, VERDICT_TX);
	return response_failure_verdict();
}

#endif
