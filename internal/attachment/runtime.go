// Package attachment manages XDP attachment lifecycle.
package attachment

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"

	"xdpass/internal/xsk"
)

// LoadFunc loads a BPF object for an attachment.
type LoadFunc func() (*ebpf.Collection, error)

// AttachXDPFunc attaches an XDP program to an interface.
type AttachXDPFunc func(prog *ebpf.Program, ifindex int, attachMode string) (link.Link, error)

// QueueProbeFunc returns the maximum RX queue count supported by an interface.
type QueueProbeFunc func(ifIndex uint32) (uint32, error)

// bpfResources holds the BPF resources for a single attachment.
type bpfResources struct {
	coll *ebpf.Collection
	link link.Link
}

func (b *bpfResources) closeLink() {
	if b.link != nil {
		b.link.Close()
		b.link = nil
	}
}

func (b *bpfResources) closeAll() {
	b.closeLink()
	if b.coll != nil {
		b.coll.Close()
		b.coll = nil
	}
}

// Runtime manages attachment state, BPF objects, and XDP links.
type Runtime struct {
	loadBPF     LoadFunc
	attachXDP   AttachXDPFunc
	queueProbe  QueueProbeFunc
	openPromisc PromiscuousOpenFunc
	mu          sync.Mutex
	attachments map[uint32]*Attachment
	resources   map[uint32]*bpfResources
	promisc     map[uint32]PromiscuousHandle

	afterCreate        XSKAfterCreateFunc
	afterPatch         XSKAfterPatchFunc
	preDelete          XSKPreDeleteFunc
	eventAfterCreate   EventAfterCreateFunc
	eventAfterPatch    EventAfterPatchFunc
	eventPreDelete     EventPreDeleteFunc
	rulesetAfterCreate RulesetAfterCreateFunc
	rulesetAfterPatch  RulesetAfterPatchFunc
	rulesetPreDelete   RulesetPreDeleteFunc
}

// SetXSKCallbacks registers XSK lifecycle callbacks.
func (r *Runtime) SetXSKCallbacks(afterCreate XSKAfterCreateFunc, afterPatch XSKAfterPatchFunc, preDelete XSKPreDeleteFunc) {
	r.afterCreate = afterCreate
	r.afterPatch = afterPatch
	r.preDelete = preDelete
}

// SetEventCallbacks registers event lifecycle callbacks.
func (r *Runtime) SetEventCallbacks(afterCreate EventAfterCreateFunc, afterPatch EventAfterPatchFunc, preDelete EventPreDeleteFunc) {
	r.eventAfterCreate = afterCreate
	r.eventAfterPatch = afterPatch
	r.eventPreDelete = preDelete
}

// SetRulesetCallbacks registers ruleset lifecycle callbacks.
func (r *Runtime) SetRulesetCallbacks(afterCreate RulesetAfterCreateFunc, afterPatch RulesetAfterPatchFunc, preDelete RulesetPreDeleteFunc) {
	r.rulesetAfterCreate = afterCreate
	r.rulesetAfterPatch = afterPatch
	r.rulesetPreDelete = preDelete
}

// New creates a new attachment runtime.
func New(loadBPF LoadFunc, attachXDP AttachXDPFunc) *Runtime {
	return &Runtime{
		loadBPF:     loadBPF,
		attachXDP:   attachXDP,
		queueProbe:  probeMaxRXQueues,
		openPromisc: openPromiscuous,
		attachments: make(map[uint32]*Attachment),
		resources:   make(map[uint32]*bpfResources),
		promisc:     make(map[uint32]PromiscuousHandle),
	}
}

// SetQueueProbe overrides the RX queue probe. It is intended for tests.
func (r *Runtime) SetQueueProbe(fn QueueProbeFunc) {
	r.queueProbe = fn
}

// SetPromiscuousOpen overrides the promiscuous mode opener. It is intended for tests.
func (r *Runtime) SetPromiscuousOpen(fn PromiscuousOpenFunc) {
	r.openPromisc = fn
}

var validAttachModes = map[string]bool{"generic": true, "native": true, "driver": true}

func (r *Runtime) normalize(req *Request) {
	if req.AttachMode == "" {
		req.AttachMode = "generic"
	}
	if req.MissVerdict == "" {
		req.MissVerdict = "pass"
	}
	if req.Channels == nil {
		req.Channels = &ChannelsConfig{}
	}
	if req.XSK == nil {
		req.XSK = &XSKConfig{}
	}
	if req.XSK.Enabled {
		req.XSK.UMEM = withDefaultUMEM(req.XSK.UMEM)
	}
	maxRXQueues, err := r.queueProbe(req.IfIndex)
	if err != nil {
		maxRXQueues = 0
	}
	req.Channels.MaxRxQueueCount = maxRXQueues
	if req.XSK.Enabled && len(req.XSK.Queues) == 0 {
		req.XSK.Queues = defaultXSKQueues(req.Channels.RxQueueCount, maxRXQueues)
	}
}

func (r *Runtime) validate(req *Request) error {
	if req.IfIndex == 0 {
		return &ValidationError{Detail: "ifindex must be greater than 0"}
	}
	if !validAttachModes[req.AttachMode] {
		return &ValidationError{Detail: fmt.Sprintf("invalid attach_mode: %s", req.AttachMode)}
	}
	if req.MissVerdict != "pass" && req.MissVerdict != "drop" {
		return &ValidationError{Detail: fmt.Sprintf("invalid miss_verdict: %s", req.MissVerdict)}
	}
	if req.XSK != nil && req.XSK.Enabled {
		if err := req.XSK.UMEM.Validate(); err != nil {
			return &ValidationError{Detail: err.Error()}
		}
		enabledQueues := enabledRXQueues(req.Channels.RxQueueCount, req.Channels.MaxRxQueueCount)
		seen := make(map[uint32]bool)
		for _, q := range req.XSK.Queues {
			if seen[q] {
				return &ValidationError{Detail: fmt.Sprintf("duplicate xsk queue: %d", q)}
			}
			if enabledQueues > 0 && q >= enabledQueues {
				return &ValidationError{Detail: fmt.Sprintf("xsk queue %d exceeds enabled rx queues %d", q, enabledQueues)}
			}
			seen[q] = true
		}
	}
	return nil
}

func (r *Runtime) buildAttachment(req *Request, programID uint32, mapSetID string) *Attachment {
	channels := ChannelsConfig{
		RxQueueCount:    req.Channels.RxQueueCount,
		MaxRxQueueCount: req.Channels.MaxRxQueueCount,
	}

	var xskCfg XSKConfig
	if req.XSK.Enabled {
		queues := make([]uint32, len(req.XSK.Queues))
		copy(queues, req.XSK.Queues)
		xskCfg = XSKConfig{Enabled: true, Queues: queues, UMEM: req.XSK.UMEM}
	}

	return &Attachment{
		IfIndex:     req.IfIndex,
		AttachMode:  req.AttachMode,
		Enabled:     true,
		MissVerdict: req.MissVerdict,
		Channels:    channels,
		XSK:         xskCfg,
		ProgramID:   programID,
		MapSetID:    mapSetID,
	}
}

// DryRun validates and normalizes a request without saving or attaching.
func (r *Runtime) DryRun(req *Request) (*Attachment, error) {
	r.normalize(req)
	if err := r.validate(req); err != nil {
		return nil, err
	}
	return r.buildAttachment(req, 0, ""), nil
}

// Create validates, loads BPF, attaches XDP, and saves the attachment.
func (r *Runtime) Create(req *Request) (*Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.normalize(req)
	if err := r.validate(req); err != nil {
		return nil, err
	}

	if _, exists := r.attachments[req.IfIndex]; exists {
		return nil, &ConflictError{IfIndex: req.IfIndex}
	}

	// Load BPF.
	coll, err := r.loadBPF()
	if err != nil {
		return nil, fmt.Errorf("load bpf: %w", err)
	}

	// Attach XDP.
	xdpLink, err := r.attachXDP(coll.Programs["xdpass_prog"], int(req.IfIndex), req.AttachMode)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach xdp: %w", err)
	}

	programID := programID(coll.Programs["xdpass_prog"])
	att := r.buildAttachment(req, programID, fmt.Sprintf("ifindex-%d", req.IfIndex))
	r.attachments[req.IfIndex] = att
	r.resources[req.IfIndex] = &bpfResources{coll: coll, link: xdpLink}
	if err := r.enablePromiscuous(req.IfIndex); err != nil {
		r.cleanup(req.IfIndex)
		return nil, fmt.Errorf("enable promiscuous mode: %w", err)
	}

	// Start XSK if enabled and callback is set.
	if att.XSK.Enabled && r.afterCreate != nil {
		if err := r.afterCreate(att, &collMapAccessor{maps: coll.Maps}); err != nil {
			// Rollback: close BPF resources and remove attachment.
			r.cleanup(req.IfIndex)
			return nil, fmt.Errorf("xsk start: %w", err)
		}
	}

	// Start event reader. Rollback on failure.
	if r.eventAfterCreate != nil {
		if err := r.eventAfterCreate(att, &collMapAccessor{maps: coll.Maps}); err != nil {
			r.cleanup(req.IfIndex)
			return nil, fmt.Errorf("event reader start: %w", err)
		}
	}

	// Apply current ruleset to the new attachment's maps.
	if r.rulesetAfterCreate != nil {
		if err := r.rulesetAfterCreate(att, &collMapAccessor{maps: coll.Maps}); err != nil {
			r.cleanup(req.IfIndex)
			return nil, fmt.Errorf("ruleset apply: %w", err)
		}
	}

	logrus.WithFields(logrus.Fields{
		"ifindex":     req.IfIndex,
		"attach_mode": req.AttachMode,
	}).Info("Attachment created")
	return att, nil
}

// Get returns an attachment by ifindex.
func (r *Runtime) Get(ifIndex uint32) (*Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	att, ok := r.attachments[ifIndex]
	if !ok {
		return nil, &NotFoundError{IfIndex: ifIndex}
	}
	return att, nil
}

// List returns all attachments.
func (r *Runtime) List() []*Attachment {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := make([]*Attachment, 0, len(r.attachments))
	for _, att := range r.attachments {
		result = append(result, att)
	}
	return result
}

// PatchEnabled toggles the enabled state of an attachment.
func (r *Runtime) PatchEnabled(ifIndex uint32, enabled bool) (*Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	att, ok := r.attachments[ifIndex]
	if !ok {
		return nil, &NotFoundError{IfIndex: ifIndex}
	}

	if att.Enabled == enabled {
		return att, nil
	}

	res, ok := r.resources[ifIndex]
	if !ok {
		return nil, fmt.Errorf("bpf resources not found for ifindex=%d", ifIndex)
	}

	if enabled {
		// Re-attach XDP using existing BPF object.
		prog := res.coll.Programs["xdpass_prog"]
		xdpLink, err := r.attachXDP(prog, int(ifIndex), att.AttachMode)
		if err != nil {
			return nil, fmt.Errorf("attach xdp: %w", err)
		}
		res.link = xdpLink
		if err := r.enablePromiscuous(ifIndex); err != nil {
			res.closeLink()
			return nil, fmt.Errorf("enable promiscuous mode: %w", err)
		}
		att.Enabled = true
		att.ProgramID = programID(prog)

		// Start XSK if enabled and callback is set.
		if att.XSK.Enabled && r.afterPatch != nil {
			if err := r.afterPatch(att, &collMapAccessor{maps: res.coll.Maps}, true); err != nil {
				res.closeLink()
				r.releasePromiscuous(ifIndex)
				att.Enabled = false
				return nil, fmt.Errorf("xsk start: %w", err)
			}
		}

		// Start event reader on enable.
		if r.eventAfterPatch != nil {
			r.eventAfterPatch(att, &collMapAccessor{maps: res.coll.Maps}, true)
		}

		// Apply current ruleset on enable. Rollback on failure.
		if r.rulesetAfterPatch != nil {
			if err := r.rulesetAfterPatch(att, &collMapAccessor{maps: res.coll.Maps}, true); err != nil {
				r.eventAfterPatch(att, &collMapAccessor{maps: res.coll.Maps}, false)
				if att.XSK.Enabled && r.afterPatch != nil {
					r.afterPatch(att, &collMapAccessor{maps: res.coll.Maps}, false)
				}
				res.closeLink()
				r.releasePromiscuous(ifIndex)
				att.Enabled = false
				return nil, fmt.Errorf("ruleset apply: %w", err)
			}
		}

		logrus.WithField("ifindex", ifIndex).Info("Attachment enabled")
	} else {
		// Notify ruleset lifecycle before disable.
		if r.rulesetAfterPatch != nil {
			r.rulesetAfterPatch(att, &collMapAccessor{maps: res.coll.Maps}, false)
		}

		// Stop event reader before disable.
		if r.eventAfterPatch != nil {
			r.eventAfterPatch(att, &collMapAccessor{maps: res.coll.Maps}, false)
		}

		// Stop XSK before detaching if callback is set.
		if att.XSK.Enabled && r.afterPatch != nil {
			r.afterPatch(att, &collMapAccessor{maps: res.coll.Maps}, false)
		}

		// Detach XDP, keep BPF object loaded for potential re-enable.
		res.closeLink()
		r.releasePromiscuous(ifIndex)
		att.Enabled = false
		att.ProgramID = 0
		logrus.WithField("ifindex", ifIndex).Info("Attachment disabled")
	}

	return att, nil
}

// Delete removes an attachment, detaching XDP and releasing BPF resources.
func (r *Runtime) Delete(ifIndex uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	att, ok := r.attachments[ifIndex]
	if !ok {
		return &NotFoundError{IfIndex: ifIndex}
	}

	// Notify ruleset lifecycle before cleanup.
	if r.rulesetPreDelete != nil {
		r.rulesetPreDelete(ifIndex, r.mapAccessorLocked(ifIndex))
	}

	// Stop event reader before cleanup.
	if r.eventPreDelete != nil {
		r.eventPreDelete(ifIndex, r.mapAccessorLocked(ifIndex))
	}

	// Stop XSK before cleanup if callback is set.
	if att.XSK.Enabled && r.preDelete != nil {
		r.preDelete(ifIndex, r.mapAccessorLocked(ifIndex))
	}

	r.cleanup(ifIndex)
	logrus.WithField("ifindex", ifIndex).Info("Attachment deleted")
	return nil
}

func (r *Runtime) cleanup(ifIndex uint32) {
	if res, ok := r.resources[ifIndex]; ok {
		res.closeAll()
		delete(r.resources, ifIndex)
	}
	r.releasePromiscuous(ifIndex)
	delete(r.attachments, ifIndex)
}

func (r *Runtime) enablePromiscuous(ifIndex uint32) error {
	if r.promisc[ifIndex] != nil {
		return nil
	}
	handle, err := r.openPromisc(ifIndex)
	if err != nil {
		return err
	}
	r.promisc[ifIndex] = handle
	logrus.WithField("ifindex", ifIndex).Debug("Requested promiscuous mode")
	return nil
}

func (r *Runtime) releasePromiscuous(ifIndex uint32) {
	handle := r.promisc[ifIndex]
	if handle == nil {
		return
	}
	if err := handle.Close(); err != nil {
		logrus.WithError(err).WithField("ifindex", ifIndex).Warn("Fail to release promiscuous mode")
	} else {
		logrus.WithField("ifindex", ifIndex).Debug("Released promiscuous mode")
	}
	delete(r.promisc, ifIndex)
}

// Close releases all BPF resources.
func (r *Runtime) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for ifIndex := range r.attachments {
		att := r.attachments[ifIndex]
		if r.rulesetPreDelete != nil {
			r.rulesetPreDelete(ifIndex, r.mapAccessorLocked(ifIndex))
		}
		if r.eventPreDelete != nil {
			r.eventPreDelete(ifIndex, r.mapAccessorLocked(ifIndex))
		}
		if att.XSK.Enabled && r.preDelete != nil {
			r.preDelete(ifIndex, r.mapAccessorLocked(ifIndex))
		}
		r.cleanup(ifIndex)
	}
}

// Maps returns the BPF map accessor for an attachment.
// Returns nil if the attachment has no BPF resources.
func (r *Runtime) Maps(ifIndex uint32) MapAccessor {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.mapAccessorLocked(ifIndex)
}

func (r *Runtime) mapAccessorLocked(ifIndex uint32) MapAccessor {
	res, ok := r.resources[ifIndex]
	if !ok || res.coll == nil {
		return nil
	}
	return &collMapAccessor{maps: res.coll.Maps}
}

// EnabledMapAccessors returns MapAccessors for all enabled attachments.
func (r *Runtime) EnabledMapAccessors() []MapAccessor {
	r.mu.Lock()
	defer r.mu.Unlock()

	var result []MapAccessor
	for ifIndex, att := range r.attachments {
		if !att.Enabled {
			continue
		}
		res, ok := r.resources[ifIndex]
		if !ok || res.coll == nil {
			continue
		}
		result = append(result, &collMapAccessor{maps: res.coll.Maps})
	}
	return result
}

// EnabledAttachments returns ifindex and MapAccessor pairs for all enabled attachments.
func (r *Runtime) EnabledAttachments() []EnabledAttachment {
	r.mu.Lock()
	defer r.mu.Unlock()

	var result []EnabledAttachment
	for ifIndex, att := range r.attachments {
		if !att.Enabled {
			continue
		}
		res, ok := r.resources[ifIndex]
		if !ok || res.coll == nil {
			continue
		}
		result = append(result, EnabledAttachment{
			IfIndex: ifIndex,
			Maps:    &collMapAccessor{maps: res.coll.Maps},
		})
	}
	return result
}

// EnabledAttachment holds an enabled attachment's ifindex and map accessor.
type EnabledAttachment struct {
	IfIndex uint32
	Maps    MapAccessor
}

// Health checks all enabled attachments for runtime inconsistencies.
// It returns a list of health issues found. An empty list means healthy.
func (r *Runtime) Health() []HealthIssue {
	r.mu.Lock()
	defer r.mu.Unlock()

	var issues []HealthIssue
	for ifIndex, att := range r.attachments {
		if !att.Enabled {
			continue
		}
		res, ok := r.resources[ifIndex]
		if !ok {
			issues = append(issues, HealthIssue{Code: "attachment_resources_missing", IfIndex: ifIndex})
			continue
		}
		if res.link == nil {
			issues = append(issues, HealthIssue{Code: "attachment_link_missing", IfIndex: ifIndex})
		}
		if res.coll == nil {
			issues = append(issues, HealthIssue{Code: "attachment_resources_missing", IfIndex: ifIndex})
			continue
		}
		if res.coll.Maps["rule_index_map"] == nil || res.coll.Maps["global_cfg_map"] == nil {
			issues = append(issues, HealthIssue{Code: "attachment_map_missing", IfIndex: ifIndex})
		}
	}
	return issues
}

// MapAccessor provides access to BPF maps for ruleset operations.
type MapAccessor interface {
	RuleIndexMap() *ebpf.Map
	GlobalCfgMap() *ebpf.Map
	TxConfigMap() *ebpf.Map
	SrcPortIndexMap() *ebpf.Map
	DstPortIndexMap() *ebpf.Map
	VlanIndexMap() *ebpf.Map
	SrcPrefixLpmMap() *ebpf.Map
	DstPrefixLpmMap() *ebpf.Map
	EventRingbufMap() *ebpf.Map
	StatsMap() *ebpf.Map
	XsksMap() *ebpf.Map
}

type collMapAccessor struct {
	maps map[string]*ebpf.Map
}

func (c *collMapAccessor) RuleIndexMap() *ebpf.Map    { return c.maps["rule_index_map"] }
func (c *collMapAccessor) GlobalCfgMap() *ebpf.Map    { return c.maps["global_cfg_map"] }
func (c *collMapAccessor) TxConfigMap() *ebpf.Map     { return c.maps["tx_config_map"] }
func (c *collMapAccessor) SrcPortIndexMap() *ebpf.Map { return c.maps["src_port_index_map"] }
func (c *collMapAccessor) DstPortIndexMap() *ebpf.Map { return c.maps["dst_port_index_map"] }
func (c *collMapAccessor) VlanIndexMap() *ebpf.Map    { return c.maps["vlan_index_map"] }
func (c *collMapAccessor) SrcPrefixLpmMap() *ebpf.Map { return c.maps["src_prefix_lpm_map"] }
func (c *collMapAccessor) DstPrefixLpmMap() *ebpf.Map { return c.maps["dst_prefix_lpm_map"] }
func (c *collMapAccessor) EventRingbufMap() *ebpf.Map { return c.maps["event_ringbuf"] }
func (c *collMapAccessor) StatsMap() *ebpf.Map        { return c.maps["stats_map"] }
func (c *collMapAccessor) XsksMap() *ebpf.Map         { return c.maps["xsks_map"] }

func programID(prog *ebpf.Program) uint32 {
	if prog == nil {
		return 0
	}
	info, err := prog.Info()
	if err != nil {
		return 0
	}
	id, ok := info.ID()
	if !ok {
		return 0
	}
	return uint32(id)
}

func defaultXSKQueues(rxQueueCount, maxRXQueueCount uint32) []uint32 {
	count := enabledRXQueues(rxQueueCount, maxRXQueueCount)
	if count == 0 {
		count = 1
	}
	queues := make([]uint32, count)
	for i := range queues {
		queues[i] = uint32(i)
	}
	return queues
}

func enabledRXQueues(rxQueueCount, maxRXQueueCount uint32) uint32 {
	if rxQueueCount > 0 {
		return rxQueueCount
	}
	return maxRXQueueCount
}

func withDefaultUMEM(opts xsk.Options) xsk.Options {
	defaults := xsk.DefaultOptions()
	if opts.FrameSize == 0 {
		opts.FrameSize = defaults.FrameSize
	}
	if opts.FrameCount == 0 {
		opts.FrameCount = defaults.FrameCount
	}
	if opts.FillRingSize == 0 {
		opts.FillRingSize = defaults.FillRingSize
	}
	if opts.CompletionRingSize == 0 {
		opts.CompletionRingSize = defaults.CompletionRingSize
	}
	if opts.RXRingSize == 0 {
		opts.RXRingSize = defaults.RXRingSize
	}
	if opts.TXRingSize == 0 {
		opts.TXRingSize = defaults.TXRingSize
	}
	if opts.TXFrameReserve == 0 {
		opts.TXFrameReserve = defaults.TXFrameReserve
	}
	return opts
}

func probeMaxRXQueues(ifIndex uint32) (uint32, error) {
	iface, err := net.InterfaceByIndex(int(ifIndex))
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(filepath.Join("/sys/class/net", iface.Name, "queues"))
	if err != nil {
		return 0, err
	}
	var count uint32
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "rx-") {
			continue
		}
		queueID, err := strconv.ParseUint(strings.TrimPrefix(name, "rx-"), 10, 32)
		if err != nil {
			continue
		}
		if next := uint32(queueID) + 1; next > count {
			count = next
		}
	}
	return count, nil
}
