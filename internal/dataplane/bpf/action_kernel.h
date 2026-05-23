#ifndef XDPASS_ACTION_KERNEL_BPF_H
#define XDPASS_ACTION_KERNEL_BPF_H

#include "action_event.h"
#include "action_verdict.h"

#define TCPHDR_LEN      20
#define IPHDR_LEN       20
#define RST_FLAGS       0x04
#define RST_ACK_FLAGS   0x14
#define TCP_DOFF_5      0x50
#define DEFAULT_TTL     64

#define TX_MODE_XDP_TX   0
#define TX_MODE_REDIRECT 1

#define VLAN_MODE_PRESERVE 0
#define VLAN_MODE_ACCESS   1

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
	__be32 orig_seq;
	__be32 orig_ack_seq;
	__u32 csum;
	__u32 ip_hdr_len;
	__u32 tcp_hdr_len;
	__u32 tcp_seg_len;
	__u32 ack_delta;
	const __u16 *p;
	int has_vlan = 0;
	__be16 vlan_encap_proto = 0;
	__u32 key = 0;
	struct tx_config *txc;
	__u8 orig_ack;

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
		has_vlan = 1;
		vlan_encap_proto = vlan->h_vlan_encapsulated_proto;
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
	ip_hdr_len = ip->ihl * 4;
	if (!ptr_ok(ip, data_end, ip_hdr_len))
		goto fail;
	offset += ip_hdr_len;

	/* Verify TCP header access. */
	tcp = data + offset;
	if (!ptr_ok(tcp, data_end, sizeof(*tcp)))
		goto fail;
	if (tcp->doff < 5)
		goto fail;
	tcp_hdr_len = tcp->doff * 4;
	if (!ptr_ok(tcp, data_end, tcp_hdr_len))
		goto fail;

	if (bpf_ntohs(ip->tot_len) < ip_hdr_len + tcp_hdr_len)
		goto fail;
	tcp_seg_len = bpf_ntohs(ip->tot_len) - ip_hdr_len;
	ack_delta = tcp_seg_len - tcp_hdr_len;
	if (tcp->syn)
		ack_delta += 1;
	if (tcp->fin)
		ack_delta += 1;
	orig_seq = tcp->seq;
	orig_ack_seq = tcp->ack_seq;
	orig_ack = tcp->ack;

	/* Swap IP addresses. */
	tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;

	/* Swap TCP ports. */
	tmp_port = tcp->source;
	tcp->source = tcp->dest;
	tcp->dest = tmp_port;

	/* RFC 793 reset generation: ACKed segments use SEG.ACK as RST SEQ.
	 * Non-ACK segments use RST|ACK with ACK = SEG.SEQ + SEG.LEN.
	 */
	if (orig_ack) {
		tcp->seq = orig_ack_seq;
		tcp->ack_seq = 0;
		*((__u8 *)tcp + 13) = RST_FLAGS;
	} else {
		tcp->seq = 0;
		tcp->ack_seq = bpf_htonl(bpf_ntohl(orig_seq) + ack_delta);
		*((__u8 *)tcp + 13) = RST_ACK_FLAGS;
	}

	/* Clear checksum and urgent pointer. */
	tcp->check = 0;
	tcp->window = 0;
	tcp->urg_ptr = 0;

	/* Set data offset = 5 (20 bytes). */
	*((__u8 *)tcp + 12) = TCP_DOFF_5;

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
	csum += bpf_htons(IPPROTO_TCP);
	csum += bpf_htons(TCPHDR_LEN);
	p = (const __u16 *)tcp;
	csum += p[0] + p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7] + p[8] + p[9];
	tcp->check = csum_fold(csum);

	/* Read TX config for send mode. */
	txc = bpf_map_lookup_elem(&tx_config_map, &key);
	if (!txc)
		goto xdp_tx;

	if (txc->tcp_reset_mode == TX_MODE_REDIRECT) {
		__u32 egress_ifindex = txc->tcp_reset_egress_ifindex;
		int ret;

		if (egress_ifindex == 0)
			goto fail_after_stats;

		/* VLAN access mode: strip VLAN tag. */
		if (has_vlan && txc->tcp_reset_vlan_mode == VLAN_MODE_ACCESS) {
			__u8 new_eth[14] = {};

			new_eth[0] = smac[0]; new_eth[1] = smac[1];
			new_eth[2] = smac[2]; new_eth[3] = smac[3];
			new_eth[4] = smac[4]; new_eth[5] = smac[5];
			new_eth[6] = dmac[0]; new_eth[7] = dmac[1];
			new_eth[8] = dmac[2]; new_eth[9] = dmac[3];
			new_eth[10] = dmac[4]; new_eth[11] = dmac[5];
			new_eth[12] = ((__u8 *)&vlan_encap_proto)[0];
			new_eth[13] = ((__u8 *)&vlan_encap_proto)[1];

			if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct vlan_hdr)) < 0)
				goto redirect_fail;

			data = (void *)(long)ctx->data;
			data_end = (void *)(long)ctx->data_end;
			eth = data;
			if (!ptr_ok(eth, data_end, sizeof(*eth)))
				goto redirect_fail;

			__builtin_memcpy(eth, new_eth, 14);
		}

		ret = bpf_redirect(egress_ifindex, 0);
		if (ret != XDP_REDIRECT)
			goto redirect_fail;

		stats_inc(STAT_KERNEL_RESPONSE_PACKETS);
		stats_inc(STAT_KERNEL_RESPONSE_REDIRECT_PACKETS);
		emit_rule_event(pkt, rule, VERDICT_REDIRECT_TX);
		return XDP_REDIRECT;
	}

xdp_tx:
	stats_inc(STAT_KERNEL_RESPONSE_PACKETS);
	stats_inc(STAT_KERNEL_RESPONSE_XDP_TX_PACKETS);
	emit_rule_event(pkt, rule, VERDICT_TX);
	return XDP_TX;

redirect_fail:
	stats_inc(STAT_KERNEL_RESPONSE_PACKETS);
	stats_inc(STAT_KERNEL_RESPONSE_ERROR_PACKETS);
	stats_inc(STAT_DIAG_REDIRECT_FAILED);
	emit_rule_event(pkt, rule, VERDICT_REDIRECT_TX);
	return response_failure_verdict();

fail_after_stats:
	stats_inc(STAT_KERNEL_RESPONSE_PACKETS);
	stats_inc(STAT_KERNEL_RESPONSE_ERROR_PACKETS);
	emit_rule_event(pkt, rule, VERDICT_REDIRECT_TX);
	return response_failure_verdict();

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
