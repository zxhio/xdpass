#ifndef XDPASS_MATCH_BPF_H
#define XDPASS_MATCH_BPF_H

#include "maps.h"

static __always_inline void apply_index_mask(struct mask_t *candidates, void *map, const void *key,
					     const struct mask_t *optional)
{
	struct mask_t *indexed = bpf_map_lookup_elem(map, key);
	if (indexed) {
#pragma unroll
		for (int i = 0; i < RULE_GROUPS; i++)
			candidates->bits[i] &= indexed->bits[i] | optional->bits[i];
	} else {
		mask_and(candidates, optional);
	}
}

static __always_inline void apply_condition_masks(struct mask_t *candidates, const struct global_cfg *cfg,
						  __u32 pkt_conds)
{
	if (!(pkt_conds & COND_PROTO_TCP))
		mask_and(candidates, &cfg->condition_optional_rules[0]);
	if (!(pkt_conds & COND_PROTO_UDP))
		mask_and(candidates, &cfg->condition_optional_rules[1]);
	if (!(pkt_conds & COND_PROTO_ICMP))
		mask_and(candidates, &cfg->condition_optional_rules[2]);
	if (!(pkt_conds & COND_PROTO_ARP))
		mask_and(candidates, &cfg->condition_optional_rules[3]);
	if (!(pkt_conds & COND_TCP_SYN))
		mask_and(candidates, &cfg->condition_optional_rules[9]);
	if (!(pkt_conds & COND_TCP_ACK))
		mask_and(candidates, &cfg->condition_optional_rules[10]);
	if (!(pkt_conds & COND_TCP_RST))
		mask_and(candidates, &cfg->condition_optional_rules[11]);
	if (!(pkt_conds & COND_TCP_FIN))
		mask_and(candidates, &cfg->condition_optional_rules[12]);
	if (!(pkt_conds & COND_TCP_PSH))
		mask_and(candidates, &cfg->condition_optional_rules[13]);
	if (!(pkt_conds & COND_ICMP_ECHO_REQUEST))
		mask_and(candidates, &cfg->condition_optional_rules[14]);
	if (!(pkt_conds & COND_ARP_REQUEST))
		mask_and(candidates, &cfg->condition_optional_rules[15]);
}

static __always_inline struct rule_meta *match_rule(struct packet_ctx *pkt, __u32 *matched_slot)
{
	__u32 key = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &key);
	struct mask_t candidates;

	if (!cfg)
		return 0;

	candidates = cfg->all_active_rules;
	if (mask_empty(&candidates))
		return 0;

	apply_index_mask(&candidates, &vlan_index_map, &pkt->vlan_id, &cfg->vlan_optional_rules);
	apply_index_mask(&candidates, &src_port_index_map, &pkt->sport, &cfg->src_port_optional_rules);
	apply_index_mask(&candidates, &dst_port_index_map, &pkt->dport, &cfg->dst_port_optional_rules);

	if (pkt->pkt_conds & (COND_PROTO_TCP | COND_PROTO_UDP | COND_PROTO_ICMP)) {
		struct ipv4_lpm_key src_key = {.prefixlen = 32, .addr = pkt->sip};
		struct ipv4_lpm_key dst_key = {.prefixlen = 32, .addr = pkt->dip};
		apply_index_mask(&candidates, &src_prefix_lpm_map, &src_key, &cfg->src_prefix_optional_rules);
		apply_index_mask(&candidates, &dst_prefix_lpm_map, &dst_key, &cfg->dst_prefix_optional_rules);
	} else {
		mask_and(&candidates, &cfg->src_prefix_optional_rules);
		mask_and(&candidates, &cfg->dst_prefix_optional_rules);
	}

	if (!mask_empty(&candidates))
		apply_condition_masks(&candidates, cfg, pkt->pkt_conds);

	if (mask_empty(&candidates))
		return 0;

	stats_inc(STAT_DIAG_RULE_CANDIDATES);

#pragma unroll
	for (int group = 0; group < RULE_GROUPS; group++) {
		__u64 bits = candidates.bits[group];
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
