#ifndef XDPASS_ACTION_VERDICT_BPF_H
#define XDPASS_ACTION_VERDICT_BPF_H

#include "maps.h"

static __always_inline int miss_verdict(void)
{
	__u32 key = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &key);
	if (!cfg)
		return XDP_PASS;
	return cfg->ingress_verdict == 1 ? XDP_DROP : XDP_PASS;
}

static __always_inline int response_failure_verdict(void)
{
	return XDP_DROP;
}

#endif
