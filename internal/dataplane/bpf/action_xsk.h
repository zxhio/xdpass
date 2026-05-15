#ifndef XDPASS_ACTION_XSK_BPF_H
#define XDPASS_ACTION_XSK_BPF_H

#include "action_event.h"
#include "action_verdict.h"

static __always_inline int apply_xsk_response(struct xdp_md *ctx, const struct packet_ctx *pkt,
					      const struct rule_meta *rule)
{
	int ret;
	__u32 queue_id = ctx->rx_queue_index;
	struct xsk_meta *meta;

	if (bpf_xdp_adjust_meta(ctx, 0 - (int)sizeof(*meta)) < 0) {
		stats_inc(STAT_XSK_REDIRECT_ERROR_PACKETS);
		stats_inc(STAT_DIAG_XSK_META_FAILED);
		return response_failure_verdict();
	}

	meta = (void *)(long)ctx->data_meta;
	if ((void *)(meta + 1) > (void *)(long)ctx->data) {
		stats_inc(STAT_XSK_REDIRECT_ERROR_PACKETS);
		stats_inc(STAT_DIAG_XSK_META_FAILED);
		return response_failure_verdict();
	}

	meta->rule_id = rule->rule_id;
	meta->action = rule->action;
	meta->reserved = 0;

	ret = bpf_redirect_map(&xsks_map, queue_id, 0);
	if (ret != XDP_REDIRECT) {
		stats_inc(STAT_XSK_REDIRECT_ERROR_PACKETS);
		stats_inc(STAT_DIAG_XSK_MAP_REDIRECT_FAILED);
		return response_failure_verdict();
	}

	stats_inc(STAT_XSK_REDIRECT_PACKETS);
	emit_rule_event(pkt, rule, VERDICT_XSK);
	return ret;
}

#endif
