#ifndef XDPASS_ACTION_EVENT_BPF_H
#define XDPASS_ACTION_EVENT_BPF_H

#include "maps.h"

static __always_inline void emit_rule_event(const struct packet_ctx *pkt, const struct rule_meta *rule,
					    __u8 verdict)
{
	struct rule_event *event = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*event), 0);
	if (!event) {
		stats_inc(STAT_EVENT_DROPPED_PACKETS);
		return;
	}

	event->timestamp_ns = bpf_ktime_get_ns();
	event->rule_id = rule->rule_id;
	event->pkt_conds = pkt->pkt_conds;
	event->sip = pkt->sip;
	event->dip = pkt->dip;
	event->action = rule->action;
	event->sport = pkt->sport;
	event->dport = pkt->dport;
	event->verdict = verdict;
	event->ip_proto = pkt->ip_proto;

	bpf_ringbuf_submit(event, 0);
}

#endif
