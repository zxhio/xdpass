// Package store provides an in-memory runtime store.
package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/cilium/ebpf"

	"xdpass/internal/api"
	"xdpass/internal/attachment"
	"xdpass/internal/dataplane/bpfgen"
	"xdpass/internal/events"
	"xdpass/internal/response"
	"xdpass/internal/ruleset"
	"xdpass/internal/stats"
)

// Store holds all in-memory runtime state.
type Store struct {
	mu               sync.RWMutex
	attachments      *attachment.Runtime
	rulesetRuntime   *ruleset.Runtime
	eventStream      *events.Stream
	responseStats    *response.Stats
	egressConfigured bool
	egressIfIndex    uint32
	egressIfName     string
	egressVLANMode   string
}

// New creates a new in-memory store.
func New(attachments *attachment.Runtime, eventStream *events.Stream, responseStats *response.Stats) *Store {
	return &Store{
		attachments:    attachments,
		rulesetRuntime: ruleset.NewRuntime(),
		eventStream:    eventStream,
		responseStats:  responseStats,
		egressVLANMode: "preserve",
	}
}

// --- Status ---

func (s *Store) Status(_ context.Context) (api.StatusResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := s.attachments.List()
	rules := s.rulesetRuntime.GetRuleset()
	return api.StatusResponse{
		Status:                   "degraded",
		Attachments:              len(list),
		RulesetLoaded:            len(rules) > 0,
		Rules:                    len(rules),
		ResponseEgressConfigured: s.egressConfigured,
	}, nil
}

// --- Attachments ---

func (s *Store) ListAttachments(_ context.Context) ([]api.AttachmentResponse, error) {
	list := s.attachments.List()
	result := make([]api.AttachmentResponse, 0, len(list))
	for _, att := range list {
		result = append(result, att.ToAPIResponse())
	}
	sort.Slice(result, func(i, j int) bool { return result[i].IfIndex < result[j].IfIndex })
	return result, nil
}

func (s *Store) GetAttachment(_ context.Context, ifIndex uint32) (api.AttachmentResponse, error) {
	att, err := s.attachments.Get(ifIndex)
	if err != nil {
		return api.AttachmentResponse{}, err
	}
	return att.ToAPIResponse(), nil
}

func (s *Store) CreateAttachment(_ context.Context, req api.AttachmentRequest) (api.AttachmentResponse, error) {
	att, err := s.attachments.Create(apiToRequest(req))
	if err != nil {
		return api.AttachmentResponse{}, err
	}
	return att.ToAPIResponse(), nil
}

func (s *Store) DryRunAttachment(_ context.Context, req api.AttachmentRequest) (api.AttachmentResponse, error) {
	att, err := s.attachments.DryRun(apiToRequest(req))
	if err != nil {
		return api.AttachmentResponse{}, err
	}
	return att.ToAPIResponse(), nil
}

func (s *Store) PatchAttachment(_ context.Context, ifIndex uint32, enabled bool) (api.AttachmentResponse, error) {
	att, err := s.attachments.PatchEnabled(ifIndex, enabled)
	if err != nil {
		return api.AttachmentResponse{}, err
	}
	return att.ToAPIResponse(), nil
}

func (s *Store) DeleteAttachment(_ context.Context, ifIndex uint32) error {
	return s.attachments.Delete(ifIndex)
}

// --- Ruleset ---

func (s *Store) GetRuleset(_ context.Context) (api.RulesetResponse, error) {
	rules := s.rulesetRuntime.GetRuleset()
	return api.RulesetResponse{Rules: rulesToAPI(rules)}, nil
}

func (s *Store) ReplaceRuleset(_ context.Context, apiRules []api.RuleResponse) (api.RulesetResponse, error) {
	internalRules := apiToRules(apiRules)
	ingressVerdict := s.getIngressVerdict()

	getMaps := func() []attachment.MapAccessor {
		return s.attachmentMapAccessors()
	}

	if err := s.rulesetRuntime.ReplaceRuleset(internalRules, ingressVerdict, getMaps); err != nil {
		return api.RulesetResponse{}, err
	}

	return api.RulesetResponse{Rules: apiRules}, nil
}

func (s *Store) DryRunRuleset(_ context.Context, apiRules []api.RuleResponse) (api.RulesetResponse, error) {
	internalRules := apiToRules(apiRules)
	ingressVerdict := s.getIngressVerdict()

	if _, err := ruleset.Compile(internalRules, ingressVerdict); err != nil {
		return api.RulesetResponse{}, err
	}

	return api.RulesetResponse{Rules: apiRules}, nil
}

func (s *Store) DeleteRuleset(_ context.Context) error {
	getMaps := func() []attachment.MapAccessor {
		return s.attachmentMapAccessors()
	}
	return s.rulesetRuntime.DeleteRuleset(getMaps)
}

// getIngressVerdict returns the miss_verdict of the first enabled attachment.
func (s *Store) getIngressVerdict() string {
	list := s.attachments.List()
	for _, att := range list {
		if att.Enabled {
			return att.MissVerdict
		}
	}
	return "pass"
}

// attachmentMapAccessors returns MapAccessors for all enabled attachments.
func (s *Store) attachmentMapAccessors() []attachment.MapAccessor {
	return s.attachments.EnabledMapAccessors()
}

// --- Stats ---

func (s *Store) GetStats(_ context.Context) (api.StatsResponse, error) {
	enabled := s.attachments.EnabledAttachments()
	var readers []stats.StatsReader
	for _, ea := range enabled {
		readers = append(readers, &mapStatsReader{m: ea.Maps.StatsMap()})
	}
	var usStats *stats.UserspaceResponseStats
	if s.responseStats != nil {
		snap := s.responseStats.Snapshot()
		usStats = &stats.UserspaceResponseStats{
			XSKRXPackets:      snap.XSKRXPackets,
			Packets:           snap.Packets,
			XSKTXPackets:      snap.XSKTXPackets,
			AFPacketTXPackets: snap.AFPacketTXPackets,
			ErrorPackets:      snap.ErrorPackets,
		}
	}
	resp := stats.SnapshotFromReaders(readers, usStats)
	return statsToAPI(resp), nil
}

type mapStatsReader struct {
	m *ebpf.Map
}

func (r *mapStatsReader) StatsMap() *ebpf.Map { return r.m }

// --- Events ---

// Subscribe creates a new event subscription.
func (s *Store) Subscribe() *api.EventSubscription {
	sub := s.eventStream.Subscribe()
	apiSub := &api.EventSubscription{
		Events: make(chan api.EventData, 64),
		Done:   make(chan struct{}),
	}
	go func() {
		for {
			select {
			case <-sub.Done:
				return
			case evt, ok := <-sub.Events:
				if !ok {
					return
				}
				apiSub.Events <- api.EventData{
					Timestamp: evt.Timestamp,
					Type:      evt.Type,
					RuleID:    evt.RuleID,
					Action:    evt.Action,
					Path:      evt.Path,
					Verdict:   evt.Verdict,
					Result:    evt.Result,
					IfIndex:   evt.IfIndex,
					SIP:       evt.SIP,
					DIP:       evt.DIP,
					Sport:     evt.Sport,
					Dport:     evt.Dport,
					IPProto:   evt.IPProto,
				}
			}
		}
	}()
	return apiSub
}

// Unsubscribe removes an event subscription.
func (s *Store) Unsubscribe(sub *api.EventSubscription) {
	close(sub.Done)
}

// --- Egress ---

func (s *Store) GetEgress(_ context.Context) (api.EgressResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return api.EgressResponse{
		Configured: s.egressConfigured,
		IfIndex:    s.egressIfIndex,
		IfName:     s.egressIfName,
		VLANMode:   s.egressVLANMode,
	}, nil
}

func (s *Store) ReplaceEgress(_ context.Context, ifIndex uint32, ifName, vlanMode string) (api.EgressResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if vlanMode == "" {
		vlanMode = "preserve"
	}
	if vlanMode != "preserve" && vlanMode != "access" {
		return api.EgressResponse{}, &api.ServiceValidationError{Detail: fmt.Sprintf("invalid vlan_mode: %s", vlanMode)}
	}

	// Write tx_config to all enabled attachments before updating memory.
	cfg := egressToTxConfig(ifIndex, vlanMode)
	if err := s.writeTxConfigToAll(cfg); err != nil {
		return api.EgressResponse{}, fmt.Errorf("write tx config: %w", err)
	}

	s.egressConfigured = true
	s.egressIfIndex = ifIndex
	s.egressIfName = ifName
	s.egressVLANMode = vlanMode

	return api.EgressResponse{
		Configured: true,
		IfIndex:    ifIndex,
		IfName:     ifName,
		VLANMode:   vlanMode,
	}, nil
}

func (s *Store) DeleteEgress(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Write default tx_config (same-port) to all enabled attachments.
	cfg := egressToTxConfig(0, "preserve")
	if err := s.writeTxConfigToAll(cfg); err != nil {
		return fmt.Errorf("write tx config: %w", err)
	}

	s.egressConfigured = false
	s.egressIfIndex = 0
	s.egressIfName = ""
	s.egressVLANMode = "preserve"
	return nil
}

// egressToTxConfig converts egress config to BPF tx_config.
func egressToTxConfig(ifIndex uint32, vlanMode string) bpfgen.XdpassTxConfig {
	cfg := bpfgen.XdpassTxConfig{
		TcpResetFailureVerdict: 1, // MVP: drop on failure
	}
	if ifIndex > 0 {
		cfg.TcpResetMode = 1 // redirect
		cfg.TcpResetEgressIfindex = ifIndex
	}
	if vlanMode == "access" {
		cfg.TcpResetVlanMode = 1
	}
	return cfg
}

// writeTxConfigToAll writes tx_config to all enabled attachments.
func (s *Store) writeTxConfigToAll(cfg bpfgen.XdpassTxConfig) error {
	enabled := s.attachments.EnabledAttachments()
	for _, ea := range enabled {
		m := ea.Maps.TxConfigMap()
		if m == nil {
			continue
		}
		if err := m.Put(uint32(0), &cfg); err != nil {
			return fmt.Errorf("ifindex %d: %w", ea.IfIndex, err)
		}
	}
	return nil
}

// --- Error helpers ---

// IsValidation checks if an error is a validation error.
func IsValidation(err error) bool {
	var ve *attachment.ValidationError
	return errors.As(err, &ve)
}

// --- Conversion helpers ---

func apiToRules(apiRules []api.RuleResponse) []ruleset.Rule {
	rules := make([]ruleset.Rule, len(apiRules))
	for i, r := range apiRules {
		rules[i] = ruleset.Rule{
			RuleID:   r.RuleID,
			Priority: r.Priority,
			Response: ruleset.Response{
				Action: r.Response.Action,
				Params: r.Response.Params,
			},
		}
		if r.Match != nil {
			rules[i].Match = apiToMatch(r.Match)
		}
	}
	return rules
}

func apiToMatch(m *api.MatchResponse) ruleset.Match {
	match := ruleset.Match{
		Protocol:     m.Protocol,
		VLANS:        m.VLANS,
		SrcCIDRs:     m.SrcCIDRs,
		DstCIDRs:     m.DstCIDRs,
		SrcPorts:     m.SrcPorts,
		DstPorts:     m.DstPorts,
		ICMPType:     m.ICMPType,
		ARPOP:        m.ARPOP,
		HasL4Payload: m.HasL4Payload,
	}
	if m.TCPFlags != nil {
		match.TCPFlags = &ruleset.TCPFlags{
			SYN: m.TCPFlags.SYN,
			ACK: m.TCPFlags.ACK,
			RST: m.TCPFlags.RST,
			FIN: m.TCPFlags.FIN,
			PSH: m.TCPFlags.PSH,
		}
	}
	return match
}

func rulesToAPI(rules []ruleset.Rule) []api.RuleResponse {
	apiRules := make([]api.RuleResponse, len(rules))
	for i, r := range rules {
		apiRules[i] = api.RuleResponse{
			RuleID:   r.RuleID,
			Priority: r.Priority,
			Response: api.ResponseResponse{
				Action: r.Response.Action,
				Params: r.Response.Params,
			},
		}
		if hasMatch(r.Match) {
			apiRules[i].Match = matchToAPI(r.Match)
		}
	}
	return apiRules
}

func hasMatch(m ruleset.Match) bool {
	return m.Protocol != "" || len(m.VLANS) > 0 || len(m.SrcCIDRs) > 0 ||
		len(m.DstCIDRs) > 0 || len(m.SrcPorts) > 0 || len(m.DstPorts) > 0 ||
		m.TCPFlags != nil || m.ICMPType != "" || m.ARPOP != "" || m.HasL4Payload != nil
}

func matchToAPI(m ruleset.Match) *api.MatchResponse {
	resp := &api.MatchResponse{
		Protocol:     m.Protocol,
		VLANS:        m.VLANS,
		SrcCIDRs:     m.SrcCIDRs,
		DstCIDRs:     m.DstCIDRs,
		SrcPorts:     m.SrcPorts,
		DstPorts:     m.DstPorts,
		ICMPType:     m.ICMPType,
		ARPOP:        m.ARPOP,
		HasL4Payload: m.HasL4Payload,
	}
	if m.TCPFlags != nil {
		resp.TCPFlags = &api.TCPFlags{
			SYN: m.TCPFlags.SYN,
			ACK: m.TCPFlags.ACK,
			RST: m.TCPFlags.RST,
			FIN: m.TCPFlags.FIN,
			PSH: m.TCPFlags.PSH,
		}
	}
	return resp
}

func apiToRequest(req api.AttachmentRequest) *attachment.Request {
	r := &attachment.Request{
		IfIndex:     req.IfIndex,
		IfName:      req.IfName,
		AttachMode:  req.AttachMode,
		MissVerdict: req.MissVerdict,
	}
	if req.Channels != nil {
		r.Channels = &attachment.ChannelsConfig{RxQueueCount: req.Channels.RxQueueCount}
	}
	if req.XSK != nil {
		queues := make([]uint32, len(req.XSK.Queues))
		copy(queues, req.XSK.Queues)
		r.XSK = &attachment.XSKConfig{Enabled: req.XSK.Enabled, Queues: queues}
	}
	return r
}

// statsToAPI converts internal stats response to API response.
func statsToAPI(resp stats.Response) api.StatsResponse {
	return api.StatsResponse{
		Ingress: api.IngressStats{
			Packets: resp.Ingress.Packets,
		},
		Parse: api.ParseStats{
			OKPackets:    resp.Parse.OKPackets,
			ErrorPackets: resp.Parse.ErrorPackets,
		},
		Match: api.MatchStats{
			HitPackets:  resp.Match.HitPackets,
			MissPackets: resp.Match.MissPackets,
		},
		KernelResponse: api.KernelResponseStats{
			Packets:         resp.KernelResponse.Packets,
			XDPTXPackets:    resp.KernelResponse.XDPTXPackets,
			RedirectPackets: resp.KernelResponse.RedirectPackets,
			ErrorPackets:    resp.KernelResponse.ErrorPackets,
		},
		XSKRedirect: api.XSKRedirectStats{
			Packets:      resp.XSKRedirect.Packets,
			ErrorPackets: resp.XSKRedirect.ErrorPackets,
		},
		UserspaceResponse: api.UserspaceResponseStats{},
		Errors: api.ErrorsStats{
			XDPPackets: resp.Errors.XDPPackets,
			XSKPackets: resp.Errors.XSKPackets,
		},
	}
}

// Ensure Store implements the service interfaces.
var (
	_ api.AttachmentService = (*Store)(nil)
	_ api.RulesetService    = (*Store)(nil)
	_ api.StatsService      = (*Store)(nil)
	_ api.EgressService     = (*Store)(nil)
	_ api.StatusService     = (*Store)(nil)
	_ api.EventStreamer     = (*Store)(nil)
)
