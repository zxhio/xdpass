package api

// --- Health / Status ---

type healthResponse struct {
	Status string `json:"status"`
}

// StatusResponse is the GET /api/v1/status response.
type StatusResponse struct {
	Status                   string `json:"status"`
	Attachments              int    `json:"attachments"`
	RulesetLoaded            bool   `json:"ruleset_loaded"`
	Rules                    int    `json:"rules"`
	ResponseEgressConfigured bool   `json:"response_egress_configured"`
}

// --- Attachments ---

// AttachmentRequest is the POST /api/v1/attachments request.
type AttachmentRequest struct {
	IfIndex     uint32           `json:"ifindex"`
	IfName      string           `json:"ifname,omitempty"`
	AttachMode  string           `json:"attach_mode,omitempty"`
	MissVerdict string           `json:"miss_verdict,omitempty"`
	Channels    *ChannelsRequest `json:"channels,omitempty"`
	XSK         *XSKRequest      `json:"xsk,omitempty"`
}

// ChannelsRequest holds RX queue channel configuration.
type ChannelsRequest struct {
	RxQueueCount uint32 `json:"rx_queue_count,omitempty"`
}

// XSKRequest holds XSK configuration.
type XSKRequest struct {
	Enabled bool     `json:"enabled,omitempty"`
	Queues  []uint32 `json:"queues,omitempty"`
}

// AttachmentResponse is the attachment resource representation.
type AttachmentResponse struct {
	IfIndex     uint32           `json:"ifindex"`
	IfName      string           `json:"ifname,omitempty"`
	AttachMode  string           `json:"attach_mode"`
	Enabled     bool             `json:"enabled"`
	MissVerdict string           `json:"miss_verdict"`
	Channels    ChannelsResponse `json:"channels"`
	XSK         XSKResponse      `json:"xsk"`
	Runtime     RuntimeResponse  `json:"runtime"`
}

// ChannelsResponse holds RX queue channel info.
type ChannelsResponse struct {
	RxQueueCount    uint32 `json:"rx_queue_count"`
	MaxRxQueueCount uint32 `json:"max_rx_queue_count"`
}

// XSKResponse holds XSK configuration.
type XSKResponse struct {
	Enabled bool     `json:"enabled"`
	Queues  []uint32 `json:"queues,omitempty"`
}

// RuntimeResponse holds runtime state.
type RuntimeResponse struct {
	ProgramID uint32 `json:"program_id"`
	MapSetID  string `json:"map_set_id,omitempty"`
}

type patchAttachmentRequest struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// --- Ruleset ---

// RulesetResponse is the GET /api/v1/ruleset response.
type RulesetResponse struct {
	Rules []RuleResponse `json:"rules"`
}

// RuleResponse is a single rule in the ruleset.
type RuleResponse struct {
	RuleID   uint32           `json:"rule_id"`
	Priority uint32           `json:"priority,omitempty"`
	Match    *MatchResponse   `json:"match,omitempty"`
	Response ResponseResponse `json:"response"`
}

// MatchResponse holds rule match conditions.
type MatchResponse struct {
	Protocol     string    `json:"protocol,omitempty"`
	VLANS        []uint16  `json:"vlans,omitempty"`
	SrcCIDRs     []string  `json:"src_cidrs,omitempty"`
	DstCIDRs     []string  `json:"dst_cidrs,omitempty"`
	SrcPorts     []uint16  `json:"src_ports,omitempty"`
	DstPorts     []uint16  `json:"dst_ports,omitempty"`
	TCPFlags     *TCPFlags `json:"tcp_flags,omitempty"`
	ICMPType     string    `json:"icmp_type,omitempty"`
	ARPOP        string    `json:"arp_op,omitempty"`
	HasL4Payload *bool     `json:"has_l4_payload,omitempty"`
}

// TCPFlags holds TCP flag match conditions.
type TCPFlags struct {
	SYN *bool `json:"syn,omitempty"`
	ACK *bool `json:"ack,omitempty"`
	RST *bool `json:"rst,omitempty"`
	FIN *bool `json:"fin,omitempty"`
	PSH *bool `json:"psh,omitempty"`
}

// ResponseResponse holds rule response action.
type ResponseResponse struct {
	Action string         `json:"action"`
	Params map[string]any `json:"params,omitempty"`
}

// --- Stats ---

// StatsResponse is the GET /api/v1/stats response.
type StatsResponse struct {
	Ingress           IngressStats           `json:"ingress"`
	Parse             ParseStats             `json:"parse"`
	Match             MatchStats             `json:"match"`
	KernelResponse    KernelResponseStats    `json:"kernel_response"`
	XSKRedirect       XSKRedirectStats       `json:"xsk_redirect"`
	UserspaceResponse UserspaceResponseStats `json:"userspace_response"`
	Errors            ErrorsStats            `json:"errors"`
}

// IngressStats holds ingress counters.
type IngressStats struct {
	Packets uint64 `json:"packets"`
}

// ParseStats holds parse counters.
type ParseStats struct {
	OKPackets    uint64 `json:"ok_packets"`
	ErrorPackets uint64 `json:"error_packets"`
}

// MatchStats holds match counters.
type MatchStats struct {
	HitPackets  uint64 `json:"hit_packets"`
	MissPackets uint64 `json:"miss_packets"`
}

// KernelResponseStats holds kernel response counters.
type KernelResponseStats struct {
	Packets         uint64 `json:"packets"`
	XDPTXPackets    uint64 `json:"xdp_tx_packets"`
	RedirectPackets uint64 `json:"redirect_packets"`
	ErrorPackets    uint64 `json:"error_packets"`
}

// XSKRedirectStats holds XSK redirect counters.
type XSKRedirectStats struct {
	Packets      uint64 `json:"packets"`
	ErrorPackets uint64 `json:"error_packets"`
}

// UserspaceResponseStats holds userspace response counters.
type UserspaceResponseStats struct {
	XSKRXPackets      uint64 `json:"xsk_rx_packets"`
	Packets           uint64 `json:"packets"`
	XSKTXPackets      uint64 `json:"xsk_tx_packets"`
	AFPacketTXPackets uint64 `json:"af_packet_tx_packets"`
	ErrorPackets      uint64 `json:"error_packets"`
}

// ErrorsStats holds error aggregation counters.
type ErrorsStats struct {
	XDPPackets uint64 `json:"xdp_packets"`
	XSKPackets uint64 `json:"xsk_packets"`
}

// --- Response Egress ---

// EgressResponse is the response egress configuration.
type EgressResponse struct {
	Configured bool   `json:"configured"`
	IfIndex    uint32 `json:"ifindex"`
	IfName     string `json:"ifname,omitempty"`
	VLANMode   string `json:"vlan_mode"`
}

type putEgressRequest struct {
	IfIndex  uint32 `json:"ifindex"`
	IfName   string `json:"ifname,omitempty"`
	VLANMode string `json:"vlan_mode,omitempty"`
}
