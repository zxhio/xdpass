// Package attachment manages XDP attachment lifecycle.
package attachment

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
)

// LoadFunc loads a BPF object for an attachment.
type LoadFunc func() (*ebpf.Collection, error)

// AttachXDPFunc attaches an XDP program to an interface.
type AttachXDPFunc func(prog *ebpf.Program, ifindex int, attachMode string) (link.Link, error)

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
	mu          sync.Mutex
	attachments map[uint32]*Attachment
	resources   map[uint32]*bpfResources

	afterCreate XSKAfterCreateFunc
	afterPatch  XSKAfterPatchFunc
	preDelete   XSKPreDeleteFunc
}

// SetXSKCallbacks registers XSK lifecycle callbacks.
func (r *Runtime) SetXSKCallbacks(afterCreate XSKAfterCreateFunc, afterPatch XSKAfterPatchFunc, preDelete XSKPreDeleteFunc) {
	r.afterCreate = afterCreate
	r.afterPatch = afterPatch
	r.preDelete = preDelete
}

// New creates a new attachment runtime.
func New(loadBPF LoadFunc, attachXDP AttachXDPFunc) *Runtime {
	return &Runtime{
		loadBPF:     loadBPF,
		attachXDP:   attachXDP,
		attachments: make(map[uint32]*Attachment),
		resources:   make(map[uint32]*bpfResources),
	}
}

var validAttachModes = map[string]bool{"generic": true, "native": true, "driver": true}

func (r *Runtime) normalize(req *Request) {
	if req.AttachMode == "" {
		req.AttachMode = "native"
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
		seen := make(map[uint32]bool)
		for _, q := range req.XSK.Queues {
			if seen[q] {
				return &ValidationError{Detail: fmt.Sprintf("duplicate xsk queue: %d", q)}
			}
			seen[q] = true
		}
	}
	return nil
}

func (r *Runtime) buildResponse(req *Request) *Attachment {
	channels := ChannelsConfig{RxQueueCount: req.Channels.RxQueueCount}

	var xskCfg XSKConfig
	if req.XSK.Enabled {
		queues := make([]uint32, len(req.XSK.Queues))
		copy(queues, req.XSK.Queues)
		xskCfg = XSKConfig{Enabled: true, Queues: queues}
	}

	return &Attachment{
		IfIndex:     req.IfIndex,
		IfName:      req.IfName,
		AttachMode:  req.AttachMode,
		Enabled:     true,
		MissVerdict: req.MissVerdict,
		Channels:    channels,
		XSK:         xskCfg,
	}
}

// DryRun validates and normalizes a request without saving or attaching.
func (r *Runtime) DryRun(req *Request) (*Attachment, error) {
	r.normalize(req)
	if err := r.validate(req); err != nil {
		return nil, err
	}
	return r.buildResponse(req), nil
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

	att := r.buildResponse(req)
	r.attachments[req.IfIndex] = att
	r.resources[req.IfIndex] = &bpfResources{coll: coll, link: xdpLink}

	// Start XSK if enabled and callback is set.
	if att.XSK.Enabled && r.afterCreate != nil {
		if err := r.afterCreate(att, &collMapAccessor{maps: coll.Maps}); err != nil {
			// Rollback: close BPF resources and remove attachment.
			r.cleanup(req.IfIndex)
			return nil, fmt.Errorf("xsk start: %w", err)
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
		att.Enabled = true

		// Start XSK if enabled and callback is set.
		if att.XSK.Enabled && r.afterPatch != nil {
			if err := r.afterPatch(att, &collMapAccessor{maps: res.coll.Maps}, true); err != nil {
				res.closeLink()
				att.Enabled = false
				return nil, fmt.Errorf("xsk start: %w", err)
			}
		}

		logrus.WithField("ifindex", ifIndex).Info("Attachment enabled")
	} else {
		// Stop XSK before detaching if callback is set.
		if att.XSK.Enabled && r.afterPatch != nil {
			r.afterPatch(att, &collMapAccessor{maps: res.coll.Maps}, false)
		}

		// Detach XDP, keep BPF object loaded for potential re-enable.
		res.closeLink()
		att.Enabled = false
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
	delete(r.attachments, ifIndex)
}

// Close releases all BPF resources.
func (r *Runtime) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for ifIndex := range r.attachments {
		att := r.attachments[ifIndex]
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
