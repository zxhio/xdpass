#ifndef XDPASS_MATCH_BPF_H
#define XDPASS_MATCH_BPF_H

#include "maps.h"

static __always_inline void apply_index_mask(struct mask_t *candidates, void *map, const void *key,
					     const struct mask_t *optional)
{
	struct mask_t *indexed = bpf_map_lookup_elem(map, key);
	if (indexed)
		mask_and(candidates, indexed);
	else
		mask_and(candidates, optional);
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

	struct ipv4_lpm_key src_key = {.prefixlen = 32, .addr = pkt->sip};
	struct ipv4_lpm_key dst_key = {.prefixlen = 32, .addr = pkt->dip};
	apply_index_mask(&candidates, &src_prefix_lpm_map, &src_key, &cfg->src_prefix_optional_rules);
	apply_index_mask(&candidates, &dst_prefix_lpm_map, &dst_key, &cfg->dst_prefix_optional_rules);

	if (mask_empty(&candidates))
		return 0;

	stats_inc(STAT_DIAG_RULE_CANDIDATES);

#pragma unroll
	for (int group = 0; group < RULE_GROUPS; group++) {
		__u64 bits = candidates.bits[group];
		if (!bits)
			continue;
#pragma unroll
		for (int bit = 0; bit < RULES_PER_GROUP; bit++) {
			if (!(bits & (1ULL << bit)))
				continue;
			__u32 slot = group * RULES_PER_GROUP + bit;
			struct rule_meta *rule = bpf_map_lookup_elem(&rule_index_map, &slot);
			if (!rule)
				continue;
			if ((pkt->pkt_conds & rule->required_mask) == rule->required_mask) {
				*matched_slot = slot;
				return rule;
			}
		}
	}

	return 0;
}

#endif
