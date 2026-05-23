// Package abi holds the shared internal ABI constants used by BPF and Go code.
package abi

const (
	RulesPerGroup = 64
	MaxRuleSlots  = 4096
	RuleGroups    = MaxRuleSlots / RulesPerGroup
	ConditionBits = 16
	StatCount     = 17
)

const (
	CondProtoTCP        uint32 = 1 << 0
	CondProtoUDP        uint32 = 1 << 1
	CondProtoICMP       uint32 = 1 << 2
	CondProtoARP        uint32 = 1 << 3
	CondVLAN            uint32 = 1 << 4
	CondSrcPrefix       uint32 = 1 << 5
	CondDstPrefix       uint32 = 1 << 6
	CondSrcPort         uint32 = 1 << 7
	CondDstPort         uint32 = 1 << 8
	CondTCPSyn          uint32 = 1 << 9
	CondTCPAck          uint32 = 1 << 10
	CondTCPRst          uint32 = 1 << 11
	CondTCPFin          uint32 = 1 << 12
	CondTCPPsh          uint32 = 1 << 13
	CondICMPEchoRequest uint32 = 1 << 14
	CondARPRequest      uint32 = 1 << 15
)

const (
	ActionNone                uint16 = 0
	ActionAlert               uint16 = 1
	ActionTCPReset            uint16 = 2
	ActionICMPEchoReply       uint16 = 3
	ActionARPReply            uint16 = 4
	ActionTCPSynAck           uint16 = 5
	ActionICMPPortUnreachable uint16 = 6
	ActionUDPEchoReply        uint16 = 7
	ActionDNSRefused          uint16 = 8
	ActionICMPHostUnreachable uint16 = 9
	ActionICMPAdminProhibited uint16 = 10
	ActionDNSSinkhole         uint16 = 11
)

const (
	StatIngressPackets             = 0
	StatParseOkPackets             = 1
	StatParseErrorPackets          = 2
	StatMatchHitPackets            = 3
	StatMatchMissPackets           = 4
	StatKernelResponsePackets      = 5
	StatKernelResponseXDPTXPackets = 6
	StatKernelResponseRedirectPkts = 7
	StatKernelResponseErrorPackets = 8
	StatXSKRedirectPackets         = 9
	StatXSKRedirectErrorPackets    = 10
	StatEventDroppedPackets        = 11
	StatDiagRuleCandidates         = 12
	StatDiagRedirectFailed         = 13
	StatDiagFibLookupFailed        = 14
	StatDiagXskMetaFailed          = 15
	StatDiagXskMapRedirectFailed   = 16
)

const (
	VerdictObserve    uint8 = 0
	VerdictTX         uint8 = 1
	VerdictXSK        uint8 = 2
	VerdictRedirectTX uint8 = 3
)
