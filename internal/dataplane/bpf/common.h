#ifndef XDPASS_COMMON_BPF_H
#define XDPASS_COMMON_BPF_H

#include "headers/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* UAPI constants not in kernel BTF */
#define ETH_P_IP      0x0800
#define ETH_P_ARP     0x0806
#define ETH_P_8021Q   0x8100
#define ETH_P_8021AD  0x88A8
#define ARPHRD_ETHER  1
#define ETH_ALEN      6
#define ICMP_ECHO     8
#define ARPOP_REQUEST 1

#define RULES_PER_GROUP 64
#define MAX_RULE_SLOTS 4096
#define RULE_GROUPS (MAX_RULE_SLOTS / RULES_PER_GROUP)
#define CONDITION_BITS 16

struct mask_t {
	__u64 bits[RULE_GROUPS];
};

struct rule_meta {
	__u32 rule_id;
	__u32 required_mask;
	__u16 action;
	__u8 flags;
};

struct global_cfg {
	struct mask_t all_active_rules;
	struct mask_t vlan_wildcard_rules;
	struct mask_t src_port_wildcard_rules;
	struct mask_t dst_port_wildcard_rules;
	struct mask_t src_prefix_wildcard_rules;
	struct mask_t dst_prefix_wildcard_rules;
	struct mask_t condition_wildcard_rules[CONDITION_BITS];
	__u32 ingress_verdict;
};

struct tx_config {
	__u32 tcp_reset_mode;
	__u32 tcp_reset_egress_ifindex;
	__u32 tcp_reset_vlan_mode;
	__u32 tcp_reset_failure_verdict;
};

struct rule_event {
	__u64 timestamp_ns;
	__u32 rule_id;
	__u32 pkt_conds;
	__u32 sip;
	__u32 dip;
	__u16 action;
	__u16 sport;
	__u16 dport;
	__u8 verdict;
	__u8 ip_proto;
};

struct xsk_meta {
	__u32 rule_id;
	__u16 action;
	__u16 reserved;
};

struct packet_ctx {
	void *data;
	void *data_end;
	__u32 pkt_conds;
	__u32 sip;
	__u32 dip;
	__u16 sport;
	__u16 dport;
	__u16 vlan_id;
	__u8 ip_proto;
	__u8 rx_queue_index;
};

enum condition_bits {
	COND_PROTO_TCP = 1 << 0,
	COND_PROTO_UDP = 1 << 1,
	COND_PROTO_ICMP = 1 << 2,
	COND_PROTO_ARP = 1 << 3,
	COND_VLAN = 1 << 4,
	COND_SRC_PREFIX = 1 << 5,
	COND_DST_PREFIX = 1 << 6,
	COND_SRC_PORT = 1 << 7,
	COND_DST_PORT = 1 << 8,
	COND_TCP_SYN = 1 << 9,
	COND_TCP_ACK = 1 << 10,
	COND_TCP_RST = 1 << 11,
	COND_TCP_FIN = 1 << 12,
	COND_TCP_PSH = 1 << 13,
	COND_ICMP_ECHO_REQUEST = 1 << 14,
	COND_ARP_REQUEST = 1 << 15,
};

enum condition_indexes {
	COND_IDX_PROTO_TCP = 0,
	COND_IDX_PROTO_UDP = 1,
	COND_IDX_PROTO_ICMP = 2,
	COND_IDX_PROTO_ARP = 3,
	COND_IDX_VLAN = 4,
	COND_IDX_SRC_PREFIX = 5,
	COND_IDX_DST_PREFIX = 6,
	COND_IDX_SRC_PORT = 7,
	COND_IDX_DST_PORT = 8,
	COND_IDX_TCP_SYN = 9,
	COND_IDX_TCP_ACK = 10,
	COND_IDX_TCP_RST = 11,
	COND_IDX_TCP_FIN = 12,
	COND_IDX_TCP_PSH = 13,
	COND_IDX_ICMP_ECHO_REQUEST = 14,
	COND_IDX_ARP_REQUEST = 15,
};

enum action_codes {
	ACTION_NONE = 0,
	ACTION_ALERT = 1,
	ACTION_TCP_RESET = 2,
	ACTION_ICMP_ECHO_REPLY = 3,
	ACTION_ARP_REPLY = 4,
	ACTION_TCP_SYN_ACK = 5,
	ACTION_ICMP_PORT_UNREACHABLE = 6,
	ACTION_UDP_ECHO_REPLY = 7,
	ACTION_DNS_REFUSED = 8,
	ACTION_ICMP_HOST_UNREACHABLE = 9,
	ACTION_ICMP_ADMIN_PROHIBITED = 10,
	ACTION_DNS_SINKHOLE = 11,
};

enum event_verdict_codes {
	VERDICT_OBSERVE = 0,
	VERDICT_TX = 1,
	VERDICT_XSK = 2,
	VERDICT_REDIRECT_TX = 3,
};

enum stats_indexes {
	STAT_INGRESS_PACKETS = 0,
	STAT_PARSE_OK_PACKETS = 1,
	STAT_PARSE_ERROR_PACKETS = 2,
	STAT_MATCH_HIT_PACKETS = 3,
	STAT_MATCH_MISS_PACKETS = 4,
	STAT_KERNEL_RESPONSE_PACKETS = 5,
	STAT_KERNEL_RESPONSE_XDP_TX_PACKETS = 6,
	STAT_KERNEL_RESPONSE_REDIRECT_PACKETS = 7,
	STAT_KERNEL_RESPONSE_ERROR_PACKETS = 8,
	STAT_XSK_REDIRECT_PACKETS = 9,
	STAT_XSK_REDIRECT_ERROR_PACKETS = 10,
	STAT_EVENT_DROPPED_PACKETS = 11,
	STAT_DIAG_RULE_CANDIDATES = 12,
	STAT_DIAG_REDIRECT_FAILED = 13,
	STAT_DIAG_FIB_LOOKUP_FAILED = 14,
	STAT_DIAG_XSK_META_FAILED = 15,
	STAT_DIAG_XSK_MAP_REDIRECT_FAILED = 16,
	STAT_COUNT = 17,
};

static __always_inline int ptr_ok(void *cursor, void *data_end, __u64 size)
{
	return cursor + size <= data_end;
}

static __always_inline int mask_empty(const struct mask_t *mask)
{
#pragma unroll
	for (int i = 0; i < RULE_GROUPS; i++) {
		if (mask->bits[i] != 0)
			return 0;
	}
	return 1;
}

static __always_inline void mask_and(struct mask_t *dst, const struct mask_t *src)
{
#pragma unroll
	for (int i = 0; i < RULE_GROUPS; i++)
		dst->bits[i] &= src->bits[i];
}

#endif
