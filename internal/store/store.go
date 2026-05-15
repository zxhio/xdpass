// Package store provides an in-memory runtime store for Phase 02.
package store

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"xdpass/internal/api"
)

// Store holds all in-memory runtime state.
type Store struct {
	mu               sync.RWMutex
	attachments      map[uint32]api.AttachmentResponse
	rules            []api.RuleResponse
	egressConfigured bool
	egressIfIndex    uint32
	egressIfName     string
	egressVLANMode   string
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{
		attachments:    make(map[uint32]api.AttachmentResponse),
		egressVLANMode: "preserve",
	}
}

// --- Status ---

// Status returns the current agent status.
func (s *Store) Status(_ context.Context) (api.StatusResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return api.StatusResponse{
		Status:                   "degraded",
		Attachments:              len(s.attachments),
		RulesetLoaded:            len(s.rules) > 0,
		Rules:                    len(s.rules),
		ResponseEgressConfigured: s.egressConfigured,
	}, nil
}

// --- Attachments ---

// ListAttachments returns all attachments.
func (s *Store) ListAttachments(_ context.Context) ([]api.AttachmentResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]api.AttachmentResponse, 0, len(s.attachments))
	for _, a := range s.attachments {
		result = append(result, a)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].IfIndex < result[j].IfIndex })
	return result, nil
}

// GetAttachment returns a single attachment by ifindex.
func (s *Store) GetAttachment(_ context.Context, ifIndex uint32) (api.AttachmentResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	a, ok := s.attachments[ifIndex]
	if !ok {
		return api.AttachmentResponse{}, fmt.Errorf("attachment ifindex=%d not found", ifIndex)
	}
	return a, nil
}

// CreateAttachment creates a new attachment.
func (s *Store) CreateAttachment(_ context.Context, req api.AttachmentRequest) (api.AttachmentResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.attachments[req.IfIndex]; exists {
		return api.AttachmentResponse{}, fmt.Errorf("attachment ifindex=%d already exists", req.IfIndex)
	}

	attachMode := req.AttachMode
	if attachMode == "" {
		attachMode = "native"
	}
	missVerdict := req.MissVerdict
	if missVerdict == "" {
		missVerdict = "pass"
	}

	resp := api.AttachmentResponse{
		IfIndex:     req.IfIndex,
		IfName:      req.IfName,
		AttachMode:  attachMode,
		Enabled:     true,
		MissVerdict: missVerdict,
		Channels:    api.ChannelsResponse{},
		XSK:         api.XSKResponse{Enabled: false},
		Runtime:     api.RuntimeResponse{},
	}

	if req.XSK != nil {
		resp.XSK.Enabled = req.XSK.Enabled
		resp.XSK.Queues = req.XSK.Queues
	}

	s.attachments[req.IfIndex] = resp
	return resp, nil
}

// PatchAttachment updates an attachment's enabled state.
func (s *Store) PatchAttachment(_ context.Context, ifIndex uint32, enabled bool) (api.AttachmentResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.attachments[ifIndex]
	if !ok {
		return api.AttachmentResponse{}, fmt.Errorf("attachment ifindex=%d not found", ifIndex)
	}

	a.Enabled = enabled
	s.attachments[ifIndex] = a
	return a, nil
}

// DeleteAttachment removes an attachment.
func (s *Store) DeleteAttachment(_ context.Context, ifIndex uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.attachments[ifIndex]; !ok {
		return fmt.Errorf("attachment ifindex=%d not found", ifIndex)
	}
	delete(s.attachments, ifIndex)
	return nil
}

// --- Ruleset ---

// GetRuleset returns the current ruleset.
func (s *Store) GetRuleset(_ context.Context) (api.RulesetResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rules := make([]api.RuleResponse, len(s.rules))
	copy(rules, s.rules)
	return api.RulesetResponse{Rules: rules}, nil
}

// ReplaceRuleset replaces the entire ruleset.
func (s *Store) ReplaceRuleset(_ context.Context, rules []api.RuleResponse) (api.RulesetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rules = make([]api.RuleResponse, len(rules))
	copy(s.rules, rules)
	return api.RulesetResponse{Rules: s.rules}, nil
}

// DeleteRuleset clears the ruleset.
func (s *Store) DeleteRuleset(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rules = nil
	return nil
}

// --- Stats ---

// GetStats returns zeroed stats (no real runtime).
func (s *Store) GetStats(_ context.Context) (api.StatsResponse, error) {
	return api.StatsResponse{}, nil
}

// --- Egress ---

// GetEgress returns the response egress configuration.
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

// ReplaceEgress replaces the response egress configuration.
func (s *Store) ReplaceEgress(_ context.Context, ifIndex uint32, ifName, vlanMode string) (api.EgressResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if vlanMode == "" {
		vlanMode = "preserve"
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

// DeleteEgress resets the response egress configuration.
func (s *Store) DeleteEgress(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.egressConfigured = false
	s.egressIfIndex = 0
	s.egressIfName = ""
	s.egressVLANMode = "preserve"
	return nil
}
