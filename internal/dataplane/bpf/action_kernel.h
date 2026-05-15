#ifndef XDPASS_ACTION_KERNEL_BPF_H
#define XDPASS_ACTION_KERNEL_BPF_H

#include "action_event.h"
#include "action_verdict.h"

static __always_inline int apply_kernel_response(struct xdp_md *ctx, const struct packet_ctx *pkt,
						 const struct rule_meta *rule)
{
	(void)ctx;
	stats_inc(STAT_KERNEL_RESPONSE_PACKETS);
	stats_inc(STAT_KERNEL_RESPONSE_ERROR_PACKETS);
	emit_rule_event(pkt, rule, VERDICT_TX);
	return response_failure_verdict();
}

#endif
