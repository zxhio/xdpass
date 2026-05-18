#ifndef XDPASS_APPLY_BPF_H
#define XDPASS_APPLY_BPF_H

#include "action_event.h"
#include "action_kernel.h"
#include "action_xsk.h"
#include "action_verdict.h"

static __always_inline int apply_action(struct xdp_md *ctx, const struct packet_ctx *pkt,
					const struct rule_meta *rule)
{
	switch (rule->action) {
	case ACTION_NONE:
	case ACTION_ALERT:
		emit_rule_event(pkt, rule, VERDICT_OBSERVE);
		return miss_verdict();
	case ACTION_TCP_RESET:
		return apply_kernel_response(ctx, pkt, rule);
	case ACTION_ICMP_PORT_UNREACHABLE:
	case ACTION_ICMP_HOST_UNREACHABLE:
	case ACTION_ICMP_ADMIN_PROHIBITED:
	case ACTION_ICMP_ECHO_REPLY:
	case ACTION_ARP_REPLY:
	case ACTION_TCP_SYN_ACK:
	case ACTION_UDP_ECHO_REPLY:
	case ACTION_DNS_REFUSED:
	case ACTION_DNS_SINKHOLE:
		return apply_xsk_response(ctx, pkt, rule);
	default:
		return miss_verdict();
	}
}

#endif
