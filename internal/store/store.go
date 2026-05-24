// Package store provides an in-memory runtime store.
package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	"xdpass/internal/api"
	"xdpass/internal/attachment"
	"xdpass/internal/dataplane/bpfgen"
	"xdpass/internal/dispatch"
	"xdpass/internal/events"
	"xdpass/internal/response"
	"xdpass/internal/ruleset"
	"xdpass/internal/stats"
	"xdpass/internal/xsk"
)

// Store holds all in-memory runtime state.
type Store struct {
	mu                sync.RWMutex
	attachments       *attachment.Runtime
	rulesetRuntime    *ruleset.Runtime
	eventStream       *events.Stream
	responseRuntime   *response.Runtime
	responseStats     *response.Stats
	xskRuntime        *xsk.Runtime
	dispatchRuntime   *dispatch.Runtime
	egressConfigured  bool
	egressIfIndex     uint32
	egressIfName      string
	egressVLANMode    string
	dispatchIfIndex   uint32
	dispatchIfName    string
	dispatchQueueSize int
	applyGeneration   map[uint32]uint64 // ifindex -> applied ruleset generation
}

// New creates a new in-memory store.
func New(attachments *attachment.Runtime, eventStream *events.Stream, responseRuntime *response.Runtime, xskRuntime *xsk.Runtime, dispatchRuntime *dispatch.Runtime) *Store {
	var rs *response.Stats
	if responseRuntime != nil {
		rs = responseRuntime.Stats()
	}
	return &Store{
		attachments:     attachments,
		rulesetRuntime:  ruleset.NewRuntime(),
		eventStream:     eventStream,
		responseRuntime: responseRuntime,
		responseStats:   rs,
		xskRuntime:      xskRuntime,
		dispatchRuntime: dispatchRuntime,
		egressVLANMode:  "preserve",
		applyGeneration: make(map[uint32]uint64),
	}
}

// WireXSKCallbacks registers XSK lifecycle callbacks on the attachment runtime.
// Must be called after New().
func (s *Store) WireXSKCallbacks() {
	if s.xskRuntime == nil || s.responseRuntime == nil {
		return
	}
	s.attachments.SetXSKCallbacks(
		s.xskAfterCreate,
		s.xskAfterPatch,
		s.xskPreDelete,
	)
}

// WireEventCallbacks registers event lifecycle callbacks on the attachment runtime.
// Must be called after New().
func (s *Store) WireEventCallbacks() {
	if s.eventStream == nil {
		return
	}
	s.attachments.SetEventCallbacks(
		s.eventAfterCreate,
		s.eventAfterPatch,
		s.eventPreDelete,
	)
}

// WireRulesetCallbacks registers ruleset lifecycle callbacks on the attachment runtime.
// Must be called after New().
func (s *Store) WireRulesetCallbacks() {
	s.attachments.SetRulesetCallbacks(
		s.rulesetAfterCreate,
		s.rulesetAfterPatch,
		s.rulesetPreDelete,
	)
}

func (s *Store) xskAfterCreate(att *attachment.Attachment, maps attachment.MapAccessor) error {
	xsksMap := maps.XsksMap()
	if xsksMap == nil {
		return fmt.Errorf("xsks_map not found")
	}

	result, err := s.xskRuntime.Start(xsksMap, xsk.StartRequest{
		IfIndex: att.IfIndex,
		Queues:  att.XSK.Queues,
		Options: att.XSK.UMEM,
	})
	if err != nil {
		return err
	}

	sockFD := result.Socket.FD()
	envCh := make(chan response.Envelope, 64)
	go func() {
		for env := range result.PktCh {
			envCh <- response.Envelope{
				Packet:  env.Packet,
				Meta:    response.XSKMeta{RuleID: env.RuleID, Action: env.Action},
				IfIndex: env.IfIndex,
			}
		}
		close(envCh)
	}()
	s.responseRuntime.StartWorker(att.IfIndex, s.currentEgressConfig(), envCh, sockFD, result.Socket, s.dispatchEnqueue, s.emitResponseResult)
	return nil
}

func (s *Store) xskAfterPatch(att *attachment.Attachment, maps attachment.MapAccessor, enabled bool) error {
	if enabled {
		return s.xskAfterCreate(att, maps)
	}
	s.xskPreDelete(att.IfIndex, maps)
	return nil
}

func (s *Store) xskPreDelete(ifIndex uint32, maps attachment.MapAccessor) {
	s.responseRuntime.StopWorker(ifIndex)

	var xsksMap *ebpf.Map
	if maps != nil {
		xsksMap = maps.XsksMap()
	}
	s.xskRuntime.Stop(xsksMap, ifIndex)
}

// eventAfterCreate starts the event ringbuf reader after attachment creation.
func (s *Store) eventAfterCreate(att *attachment.Attachment, maps attachment.MapAccessor) error {
	ringbufMap := maps.EventRingbufMap()
	if ringbufMap == nil {
		return nil
	}
	return s.eventStream.StartReader(ringbufMap, att.IfIndex)
}

// eventAfterPatch starts or stops the event ringbuf reader on enable/disable.
func (s *Store) eventAfterPatch(att *attachment.Attachment, maps attachment.MapAccessor, enabled bool) {
	if enabled {
		ringbufMap := maps.EventRingbufMap()
		if ringbufMap == nil {
			return
		}
		if err := s.eventStream.StartReader(ringbufMap, att.IfIndex); err != nil {
			logrus.WithError(err).WithField("ifindex", att.IfIndex).Warn("Failed to restart event reader")
		}
		return
	}
	s.eventStream.StopReader(att.IfIndex)
}

// eventPreDelete stops the event ringbuf reader before attachment deletion.
func (s *Store) eventPreDelete(ifIndex uint32, _ attachment.MapAccessor) {
	s.eventStream.StopReader(ifIndex)
}

// emitResponseResult broadcasts a userspace response result event.
func (s *Store) emitResponseResult(ifIndex, ruleID uint32, action, result string) {
	if s.eventStream == nil {
		return
	}
	s.eventStream.Broadcast(events.NewResultEvent(ruleID, action, ifIndex, result))
}

// rulesetAfterCreate applies the current ruleset to a newly created attachment.
func (s *Store) rulesetAfterCreate(att *attachment.Attachment, maps attachment.MapAccessor) error {
	compiled, gen := s.rulesetRuntime.CurrentCompiled()
	if compiled == nil {
		return nil
	}
	if maps == nil || maps.RuleIndexMap() == nil {
		return fmt.Errorf("write ruleset maps: maps not available")
	}
	if err := ruleset.WriteMaps(maps, compiled); err != nil {
		return fmt.Errorf("write ruleset maps: %w", err)
	}
	s.applyGeneration[att.IfIndex] = gen
	return nil
}

// rulesetAfterPatch applies the current ruleset when an attachment is enabled,
// or clears the apply generation when disabled.
func (s *Store) rulesetAfterPatch(att *attachment.Attachment, maps attachment.MapAccessor, enabled bool) error {
	if !enabled {
		delete(s.applyGeneration, att.IfIndex)
		return nil
	}
	compiled, gen := s.rulesetRuntime.CurrentCompiled()
	if compiled == nil {
		return nil
	}
	if maps == nil || maps.RuleIndexMap() == nil {
		return fmt.Errorf("write ruleset maps: maps not available")
	}
	if err := ruleset.WriteMaps(maps, compiled); err != nil {
		return fmt.Errorf("write ruleset maps: %w", err)
	}
	s.applyGeneration[att.IfIndex] = gen
	return nil
}

// rulesetPreDelete cleans up the apply generation record before attachment deletion.
func (s *Store) rulesetPreDelete(ifIndex uint32, _ attachment.MapAccessor) {
	delete(s.applyGeneration, ifIndex)
}

// dispatchEnqueue is called after a successful response to enqueue the original packet for dispatch.
func (s *Store) dispatchEnqueue(origPkt []byte) {
	if s.dispatchRuntime == nil {
		return
	}
	// Copy the packet since the original may be reused by the caller.
	pkt := make([]byte, len(origPkt))
	copy(pkt, origPkt)
	s.dispatchRuntime.TryEnqueue(pkt)
}

func (s *Store) currentEgressConfig() response.EgressConfig {
	return response.EgressConfig{
		Configured:    s.egressConfigured,
		EgressIfIndex: s.egressIfIndex,
		VLANMode:      s.egressVLANMode,
	}
}

func (s *Store) updateResponseRules(apiRules []api.RuleResponse) {
	if s.responseRuntime == nil {
		return
	}
	entries := make([]response.RuleEntry, len(apiRules))
	for i, r := range apiRules {
		entries[i] = response.RuleEntry{
			RuleID: r.RuleID,
			Action: r.Response.Action,
			Params: r.Response.Params,
		}
	}
	s.responseRuntime.UpdateRules(entries)
}

// --- Status ---

func (s *Store) Status(_ context.Context) (api.StatusResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := s.attachments.List()
	rules := s.rulesetRuntime.GetRuleset()

	var issues []api.StatusIssue

	// Attachment health (resources, link, maps).
	for _, hi := range s.attachments.Health() {
		issues = append(issues, api.StatusIssue{Component: "attachment", Code: hi.Code, IfIndex: hi.IfIndex})
	}

	// Per-attachment event/xsk/response health.
	for _, att := range list {
		if !att.Enabled {
			continue
		}
		if s.eventStream != nil && s.attachments.HasEventRingbuf(att.IfIndex) && !s.eventStream.HasReader(att.IfIndex) {
			issues = append(issues, api.StatusIssue{Component: "events", Code: "event_reader_missing", IfIndex: att.IfIndex})
		}
		if att.XSK.Enabled {
			if s.xskRuntime != nil && !s.xskRuntime.HasSocket(att.IfIndex) {
				issues = append(issues, api.StatusIssue{Component: "xsk", Code: "xsk_not_running", IfIndex: att.IfIndex})
			}
			if s.responseRuntime != nil && !s.responseRuntime.HasWorker(att.IfIndex) {
				issues = append(issues, api.StatusIssue{Component: "response", Code: "response_worker_missing", IfIndex: att.IfIndex})
			}
		}
	}

	// Dispatch health.
	if s.dispatchRuntime != nil && s.dispatchRuntime.IsEnabled() {
		if !s.dispatchRuntime.HasWorker() {
			issues = append(issues, api.StatusIssue{Component: "dispatch", Code: "dispatch_worker_missing"})
		}
		if !s.dispatchRuntime.HasSender() {
			issues = append(issues, api.StatusIssue{Component: "dispatch", Code: "dispatch_sender_missing"})
		}
	}

	// Ruleset health.
	if len(rules) > 0 {
		if s.rulesetRuntime.HasUserspaceActions() {
			for _, att := range list {
				if att.Enabled && !att.XSK.Enabled {
					issues = append(issues, api.StatusIssue{Component: "ruleset", Code: "userspace_action_without_xsk", IfIndex: att.IfIndex})
				}
			}
		}
		_, gen := s.rulesetRuntime.CurrentCompiled()
		for _, att := range list {
			if !att.Enabled {
				continue
			}
			if appliedGen, ok := s.applyGeneration[att.IfIndex]; !ok || appliedGen != gen {
				issues = append(issues, api.StatusIssue{Component: "ruleset", Code: "ruleset_not_applied", IfIndex: att.IfIndex})
			}
		}
	}

	status := "running"
	if len(issues) > 0 {
		status = "degraded"
	}

	return api.StatusResponse{
		Status:                   status,
		Attachments:              len(list),
		RulesetLoaded:            len(rules) > 0,
		Rules:                    len(rules),
		ResponseEgressConfigured: s.egressConfigured,
		DispatchConfigured:       s.dispatchRuntime != nil && s.dispatchRuntime.IsEnabled(),
		Issues:                   issues,
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
		if IsValidation(err) {
			return api.AttachmentResponse{}, &api.ServiceValidationError{Detail: err.Error()}
		}
		return api.AttachmentResponse{}, err
	}
	return att.ToAPIResponse(), nil
}

func (s *Store) DryRunAttachment(_ context.Context, req api.AttachmentRequest) (api.AttachmentResponse, error) {
	att, err := s.attachments.DryRun(apiToRequest(req))
	if err != nil {
		if IsValidation(err) {
			return api.AttachmentResponse{}, &api.ServiceValidationError{Detail: err.Error()}
		}
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
	attachments := len(s.attachmentMapAccessors())

	if err := s.rulesetRuntime.ReplaceRuleset(internalRules, ingressVerdict, getMaps); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"rules":           len(apiRules),
			"attachments":     attachments,
			"ingress_verdict": ingressVerdict,
		}).Error("Fail to replace ruleset")
		return api.RulesetResponse{}, err
	}

	// Update apply generation for all enabled attachments.
	_, gen := s.rulesetRuntime.CurrentCompiled()
	for _, ea := range s.attachments.EnabledAttachments() {
		s.applyGeneration[ea.IfIndex] = gen
	}

	// Update response worker rule lookup.
	s.updateResponseRules(apiRules)

	logrus.WithFields(logrus.Fields{
		"rules":           len(apiRules),
		"attachments":     attachments,
		"ingress_verdict": ingressVerdict,
	}).Info("Replaced ruleset")

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
	attachments := len(s.attachmentMapAccessors())
	if err := s.rulesetRuntime.DeleteRuleset(getMaps); err != nil {
		logrus.WithError(err).WithField("attachments", attachments).Error("Fail to delete ruleset")
		return err
	}

	// Clear response worker rule lookup.
	s.updateResponseRules(nil)

	// Clear all apply generation records.
	s.applyGeneration = make(map[uint32]uint64)

	logrus.WithFields(logrus.Fields{
		"attachments": attachments,
	}).Info("Deleted ruleset")
	return nil
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
	var dsStats *stats.DispatchStats
	if s.dispatchRuntime != nil {
		snap := s.dispatchRuntime.Stats().Snapshot()
		dsStats = &stats.DispatchStats{
			EnqueuePackets:   snap.EnqueuePackets,
			Packets:          snap.Packets,
			DroppedPackets:   snap.DroppedPackets,
			QueueFullPackets: snap.QueueFullPackets,
			ErrorPackets:     snap.ErrorPackets,
		}
	}
	resp := stats.SnapshotFromReaders(readers, usStats, dsStats)
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

	// Validate ifName matches ifIndex when both are provided.
	if ifName != "" {
		iface, err := net.InterfaceByName(ifName)
		if err != nil {
			return api.EgressResponse{}, &api.ServiceValidationError{Detail: fmt.Sprintf("interface not found: %s", ifName)}
		}
		if uint32(iface.Index) != ifIndex {
			return api.EgressResponse{}, &api.ServiceValidationError{Detail: fmt.Sprintf("ifname %s does not match ifindex %d", ifName, ifIndex)}
		}
	}

	// Write tx_config to all enabled attachments before updating memory.
	cfg := egressToTxConfig(ifIndex, vlanMode)
	written, err := s.writeTxConfigToAll(cfg)
	if err != nil {
		return api.EgressResponse{}, fmt.Errorf("write tx config: %w", err)
	}

	s.egressConfigured = true
	s.egressIfIndex = ifIndex
	s.egressIfName = ifName
	s.egressVLANMode = vlanMode

	if s.responseRuntime != nil {
		s.responseRuntime.UpdateEgress(response.EgressConfig{
			Configured:    true,
			EgressIfIndex: ifIndex,
			VLANMode:      vlanMode,
		})
	}

	logrus.WithFields(logrus.Fields{
		"ifindex":     ifIndex,
		"ifname":      ifName,
		"vlan_mode":   vlanMode,
		"attachments": written,
	}).Info("Replaced response egress")

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
	written, err := s.writeTxConfigToAll(cfg)
	if err != nil {
		return fmt.Errorf("reset tx config: %w", err)
	}

	s.egressConfigured = false
	s.egressIfIndex = 0
	s.egressIfName = ""
	s.egressVLANMode = "preserve"

	if s.responseRuntime != nil {
		s.responseRuntime.UpdateEgress(response.EgressConfig{
			VLANMode: "preserve",
		})
	}

	logrus.WithFields(logrus.Fields{
		"attachments": written,
	}).Info("Deleted response egress")

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
func (s *Store) writeTxConfigToAll(cfg bpfgen.XdpassTxConfig) (int, error) {
	enabled := s.attachments.EnabledAttachments()
	written := 0
	for _, ea := range enabled {
		m := ea.Maps.TxConfigMap()
		if m == nil {
			continue
		}
		if err := m.Put(uint32(0), &cfg); err != nil {
			return written, fmt.Errorf("ifindex %d: %w", ea.IfIndex, err)
		}
		written++
	}
	return written, nil
}

// --- Dispatch ---

func (s *Store) GetDispatch(_ context.Context) (api.DispatchResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.dispatchRuntime == nil || !s.dispatchRuntime.IsEnabled() {
		return api.DispatchResponse{
			QueueSize: dispatch.DefaultQueueSize,
		}, nil
	}

	// Return the current configured state from the runtime's config.
	// We store the config separately since the runtime doesn't expose it.
	return s.currentDispatchResponse(), nil
}

func (s *Store) currentDispatchResponse() api.DispatchResponse {
	// The config is stored in the store's fields set during ReplaceDispatch.
	return api.DispatchResponse{
		Enabled:    true,
		Configured: true,
		IfIndex:    s.dispatchIfIndex,
		IfName:     s.dispatchIfName,
		QueueSize:  s.dispatchQueueSize,
	}
}

func (s *Store) ReplaceDispatch(_ context.Context, req api.PutDispatchRequest) (api.DispatchResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req.IfIndex == 0 {
		return api.DispatchResponse{}, &api.ServiceValidationError{Detail: "ifindex must be greater than 0"}
	}

	// Validate ifName matches ifIndex when both are provided.
	if req.IfName != "" {
		iface, err := net.InterfaceByName(req.IfName)
		if err != nil {
			return api.DispatchResponse{}, &api.ServiceValidationError{Detail: fmt.Sprintf("interface not found: %s", req.IfName)}
		}
		if uint32(iface.Index) != req.IfIndex {
			return api.DispatchResponse{}, &api.ServiceValidationError{Detail: fmt.Sprintf("ifname %s does not match ifindex %d", req.IfName, req.IfIndex)}
		}
	}

	opts := dispatch.Options{QueueSize: req.QueueSize}
	if err := opts.Validate(); err != nil {
		return api.DispatchResponse{}, &api.ServiceValidationError{Detail: err.Error()}
	}

	// Create AF_PACKET sender for the dispatch interface.
	sender, err := response.NewAFPacketSender(req.IfIndex)
	if err != nil {
		return api.DispatchResponse{}, fmt.Errorf("create dispatch sender: %w", err)
	}

	if err := s.dispatchRuntime.Start(sender, opts); err != nil {
		sender.Close()
		return api.DispatchResponse{}, fmt.Errorf("start dispatch: %w", err)
	}

	s.dispatchIfIndex = req.IfIndex
	s.dispatchIfName = req.IfName
	s.dispatchQueueSize = opts.QueueSize

	logrus.WithFields(logrus.Fields{
		"ifindex":    req.IfIndex,
		"ifname":     req.IfName,
		"queue_size": opts.QueueSize,
	}).Info("Replaced dispatch")

	return api.DispatchResponse{
		Enabled:    true,
		Configured: true,
		IfIndex:    req.IfIndex,
		IfName:     req.IfName,
		QueueSize:  opts.QueueSize,
	}, nil
}

func (s *Store) DeleteDispatch(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dispatchRuntime != nil {
		s.dispatchRuntime.Stop()
	}

	s.dispatchIfIndex = 0
	s.dispatchIfName = ""
	s.dispatchQueueSize = 0

	logrus.Info("Deleted dispatch")
	return nil
}

// --- Error helpers ---

// IsValidation checks if an error is a validation error.
func IsValidation(err error) bool {
	var ve *attachment.ValidationError
	var se *api.ServiceValidationError
	return errors.As(err, &ve) || errors.As(err, &se)
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
		Protocol: m.Protocol,
		VLANS:    m.VLANS,
		SrcCIDRs: m.SrcCIDRs,
		DstCIDRs: m.DstCIDRs,
		SrcPorts: m.SrcPorts,
		DstPorts: m.DstPorts,
	}
	if m.TCP != nil {
		match.TCP = &ruleset.TCPMatch{
			Flags: apiToTCPFlags(m.TCP.Flags),
		}
	}
	if m.ICMP != nil {
		match.ICMP = &ruleset.ICMPMatch{Type: m.ICMP.Type}
	}
	if m.ARP != nil {
		match.ARP = &ruleset.ARPMatch{Op: m.ARP.Op}
	}
	return match
}

func apiToTCPFlags(flags *api.TCPFlags) *ruleset.TCPFlags {
	if flags == nil {
		return nil
	}
	return &ruleset.TCPFlags{
		SYN: copyBoolPtr(flags.SYN),
		ACK: copyBoolPtr(flags.ACK),
		RST: copyBoolPtr(flags.RST),
		FIN: copyBoolPtr(flags.FIN),
		PSH: copyBoolPtr(flags.PSH),
	}
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
		m.TCP != nil || m.ICMP != nil || m.ARP != nil
}

func matchToAPI(m ruleset.Match) *api.MatchResponse {
	resp := &api.MatchResponse{
		Protocol: m.Protocol,
		VLANS:    m.VLANS,
		SrcCIDRs: m.SrcCIDRs,
		DstCIDRs: m.DstCIDRs,
		SrcPorts: m.SrcPorts,
		DstPorts: m.DstPorts,
	}
	if m.TCP != nil {
		resp.TCP = &api.TCPMatch{
			Flags: tcpFlagsToAPI(m.TCP.Flags),
		}
	}
	if m.ICMP != nil {
		resp.ICMP = &api.ICMPMatch{Type: m.ICMP.Type}
	}
	if m.ARP != nil {
		resp.ARP = &api.ARPMatch{Op: m.ARP.Op}
	}
	return resp
}

func tcpFlagsToAPI(flags *ruleset.TCPFlags) *api.TCPFlags {
	if flags == nil {
		return nil
	}
	return &api.TCPFlags{
		SYN: copyBoolPtr(flags.SYN),
		ACK: copyBoolPtr(flags.ACK),
		RST: copyBoolPtr(flags.RST),
		FIN: copyBoolPtr(flags.FIN),
		PSH: copyBoolPtr(flags.PSH),
	}
}

func copyBoolPtr(v *bool) *bool {
	if v == nil {
		return nil
	}
	value := *v
	return &value
}

func apiToRequest(req api.AttachmentRequest) *attachment.Request {
	r := &attachment.Request{
		IfIndex:     req.IfIndex,
		AttachMode:  req.AttachMode,
		MissVerdict: req.MissVerdict,
	}
	if req.Channels != nil {
		r.Channels = &attachment.ChannelsConfig{RxQueueCount: req.Channels.RxQueueCount}
	}
	if req.XSK != nil {
		queues := make([]uint32, len(req.XSK.Queues))
		copy(queues, req.XSK.Queues)
		r.XSK = &attachment.XSKConfig{
			Enabled: req.XSK.Enabled,
			Queues:  queues,
			UMEM:    apiToUMEM(req.XSK.UMEM),
		}
	}
	return r
}

func apiToUMEM(req *api.UMEMRequest) xsk.Options {
	if req == nil {
		return xsk.Options{}
	}
	return xsk.Options{
		FrameSize:          req.FrameSize,
		FrameCount:         req.FrameCount,
		FillRingSize:       req.FillRingSize,
		CompletionRingSize: req.CompletionRingSize,
		RXRingSize:         req.RXRingSize,
		TXRingSize:         req.TXRingSize,
		TXFrameReserve:     req.TXFrameReserve,
	}
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
		UserspaceResponse: api.UserspaceResponseStats{
			XSKRXPackets:      resp.UserspaceResponse.XSKRXPackets,
			Packets:           resp.UserspaceResponse.Packets,
			XSKTXPackets:      resp.UserspaceResponse.XSKTXPackets,
			AFPacketTXPackets: resp.UserspaceResponse.AFPacketTXPackets,
			ErrorPackets:      resp.UserspaceResponse.ErrorPackets,
		},
		Dispatch: api.DispatchStats{
			EnqueuePackets:   resp.Dispatch.EnqueuePackets,
			Packets:          resp.Dispatch.Packets,
			DroppedPackets:   resp.Dispatch.DroppedPackets,
			QueueFullPackets: resp.Dispatch.QueueFullPackets,
			ErrorPackets:     resp.Dispatch.ErrorPackets,
		},
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
	_ api.DispatchService   = (*Store)(nil)
)
