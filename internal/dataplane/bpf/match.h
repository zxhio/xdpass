#ifndef XDPASS_MATCH_BPF_H
#define XDPASS_MATCH_BPF_H

#include "maps.h"

static __always_inline void mask_copy(struct mask_t *dst, const struct mask_t *src)
{
#pragma unroll
	for (int i = 0; i < RULE_GROUPS; i++)
		dst->bits[i] = src->bits[i];
}

static __always_inline void filter_by_index_or_wildcard(struct mask_t *candidates, void *map,
							const void *key,
							const struct mask_t *wildcard_rules)
{
	struct mask_t *indexed = bpf_map_lookup_elem(map, key);
	if (indexed) {
#pragma unroll
		for (int i = 0; i < RULE_GROUPS; i++)
			candidates->bits[i] &= indexed->bits[i] | wildcard_rules->bits[i];
	} else {
		mask_and(candidates, wildcard_rules);
	}
}

static __always_inline void filter_missing_condition(struct mask_t *candidates,
						     const struct global_cfg *cfg, __u32 pkt_conds,
						     __u32 condition, __u32 index)
{
	if (!(pkt_conds & condition))
		mask_and(candidates, &cfg->condition_wildcard_rules[index]);
}

static __always_inline void apply_condition_masks(struct mask_t *candidates, const struct global_cfg *cfg,
						  __u32 pkt_conds)
{
	filter_missing_condition(candidates, cfg, pkt_conds, COND_PROTO_TCP, COND_IDX_PROTO_TCP);
	filter_missing_condition(candidates, cfg, pkt_conds, COND_PROTO_UDP, COND_IDX_PROTO_UDP);
	filter_missing_condition(candidates, cfg, pkt_conds, COND_PROTO_ICMP, COND_IDX_PROTO_ICMP);
	filter_missing_condition(candidates, cfg, pkt_conds, COND_PROTO_ARP, COND_IDX_PROTO_ARP);
	filter_missing_condition(candidates, cfg, pkt_conds, COND_TCP_SYN, COND_IDX_TCP_SYN);
	filter_missing_condition(candidates, cfg, pkt_conds, COND_TCP_ACK, COND_IDX_TCP_ACK);
	filter_missing_condition(candidates, cfg, pkt_conds, COND_TCP_RST, COND_IDX_TCP_RST);
	filter_missing_condition(candidates, cfg, pkt_conds, COND_TCP_FIN, COND_IDX_TCP_FIN);
	filter_missing_condition(candidates, cfg, pkt_conds, COND_TCP_PSH, COND_IDX_TCP_PSH);
	filter_missing_condition(candidates, cfg, pkt_conds, COND_ICMP_ECHO_REQUEST,
				 COND_IDX_ICMP_ECHO_REQUEST);
	filter_missing_condition(candidates, cfg, pkt_conds, COND_ARP_REQUEST,
				 COND_IDX_ARP_REQUEST);
}

static __always_inline int packet_has_prefix_fields(struct packet_ctx *pkt)
{
	return pkt->pkt_conds & (COND_PROTO_TCP | COND_PROTO_UDP | COND_PROTO_ICMP | COND_PROTO_ARP);
}

static __always_inline struct rule_meta *match_rule(struct packet_ctx *pkt, __u32 *matched_slot)
{
	__u32 key = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &key);
	struct mask_t *candidates = bpf_map_lookup_elem(&match_scratch_map, &key);

	if (!cfg || !candidates)
		return 0;

	mask_copy(candidates, &cfg->all_active_rules);
	if (mask_empty(candidates))
		return 0;

	filter_by_index_or_wildcard(candidates, &vlan_index_map, &pkt->vlan_id,
				    &cfg->vlan_wildcard_rules);
	filter_by_index_or_wildcard(candidates, &src_port_index_map, &pkt->sport,
				    &cfg->src_port_wildcard_rules);
	filter_by_index_or_wildcard(candidates, &dst_port_index_map, &pkt->dport,
				    &cfg->dst_port_wildcard_rules);

	if (packet_has_prefix_fields(pkt)) {
		struct ipv4_lpm_key src_key = {.prefixlen = 32, .addr = pkt->sip};
		struct ipv4_lpm_key dst_key = {.prefixlen = 32, .addr = pkt->dip};

		filter_by_index_or_wildcard(candidates, &src_prefix_lpm_map, &src_key,
					    &cfg->src_prefix_wildcard_rules);
		filter_by_index_or_wildcard(candidates, &dst_prefix_lpm_map, &dst_key,
					    &cfg->dst_prefix_wildcard_rules);
	} else {
		mask_and(candidates, &cfg->src_prefix_wildcard_rules);
		mask_and(candidates, &cfg->dst_prefix_wildcard_rules);
	}

	if (!mask_empty(candidates))
		apply_condition_masks(candidates, cfg, pkt->pkt_conds);

	if (mask_empty(candidates))
		return 0;

	stats_inc(STAT_DIAG_RULE_CANDIDATES);

#pragma unroll
	for (int group = 0; group < RULE_GROUPS; group++) {
		__u64 bits = candidates->bits[group];
		if (!bits)
			continue;
		__u32 bit = __builtin_ctzll(bits);
		__u32 slot = group * RULES_PER_GROUP + bit;
		struct rule_meta *rule = bpf_map_lookup_elem(&rule_index_map, &slot);
		if (!rule)
			return 0;
		*matched_slot = slot;
		return rule;
	}

	return 0;
}

#endif
