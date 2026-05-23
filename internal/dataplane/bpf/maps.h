#ifndef XDPASS_MAPS_BPF_H
#define XDPASS_MAPS_BPF_H

#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULE_SLOTS);
	__type(key, __u32);
	__type(value, struct rule_meta);
} rule_index_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct global_cfg);
} global_cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tx_config);
} tx_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct mask_t);
} match_scratch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u16);
	__type(value, struct mask_t);
} src_port_index_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u16);
	__type(value, struct mask_t);
} dst_port_index_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u16);
	__type(value, struct mask_t);
} vlan_index_map SEC(".maps");

struct ipv4_lpm_key {
	__u32 prefixlen;
	__u32 addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ipv4_lpm_key);
	__type(value, struct mask_t);
} src_prefix_lpm_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ipv4_lpm_key);
	__type(value, struct mask_t);
} dst_prefix_lpm_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024);
} event_ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} xsks_map SEC(".maps");

static __always_inline void stats_inc(__u32 index)
{
	__u64 *value = bpf_map_lookup_elem(&stats_map, &index);
	if (value)
		__sync_fetch_and_add(value, 1);
}

#endif
