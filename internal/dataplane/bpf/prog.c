#include "common.h"
#include "maps.h"
#include "parse.h"
#include "match.h"
#include "apply.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("xdp")
int xdpass_prog(struct xdp_md *ctx)
{
	struct packet_ctx pkt = {};
	struct rule_meta *rule;
	__u32 slot = 0;

	stats_inc(STAT_INGRESS_PACKETS);

	if (parse_packet(ctx, &pkt) < 0) {
		stats_inc(STAT_PARSE_ERROR_PACKETS);
		return miss_verdict();
	}
	stats_inc(STAT_PARSE_OK_PACKETS);

	rule = match_rule(&pkt, &slot);
	if (!rule) {
		stats_inc(STAT_MATCH_MISS_PACKETS);
		return miss_verdict();
	}
	stats_inc(STAT_MATCH_HIT_PACKETS);

	return apply_action(ctx, &pkt, rule);
}
