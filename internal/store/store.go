// Package store provides an in-memory runtime store.
package store

import (
	"context"
	"errors"
	"sort"
	"sync"

	"xdpass/internal/api"
	"xdpass/internal/attachment"
)

// Store holds all in-memory runtime state.
type Store struct {
	mu               sync.RWMutex
	attachments      *attachment.Runtime
	rules            []api.RuleResponse
	egressConfigured bool
	egressIfIndex    uint32
	egressIfName     string
	egressVLANMode   string
}

// New creates a new in-memory store.
func New(attachments *attachment.Runtime) *Store {
	return &Store{
		attachments:   attachments,
		egressVLANMode: "preserve",
	}
}

// --- Status ---

func (s *Store) Status(_ context.Context) (api.StatusResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := s.attachments.List()
	return api.StatusResponse{
		Status:                   "degraded",
		Attachments:              len(list),
		RulesetLoaded:            len(s.rules) > 0,
		Rules:                    len(s.rules),
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
	s.mu.RLock()
	defer s.mu.RUnlock()

	rules := make([]api.RuleResponse, len(s.rules))
	copy(rules, s.rules)
	return api.RulesetResponse{Rules: rules}, nil
}

func (s *Store) ReplaceRuleset(_ context.Context, rules []api.RuleResponse) (api.RulesetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rules = make([]api.RuleResponse, len(rules))
	copy(s.rules, rules)
	return api.RulesetResponse{Rules: s.rules}, nil
}

func (s *Store) DeleteRuleset(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rules = nil
	return nil
}

// --- Stats ---

func (s *Store) GetStats(_ context.Context) (api.StatsResponse, error) {
	return api.StatsResponse{}, nil
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

	s.egressConfigured = false
	s.egressIfIndex = 0
	s.egressIfName = ""
	s.egressVLANMode = "preserve"
	return nil
}

// --- Error helpers ---

// IsConflict checks if an error is a conflict error.
func IsConflict(err error) bool {
	var ce *attachment.ConflictError
	return errors.As(err, &ce)
}

// IsNotFound checks if an error is a not-found error.
func IsNotFound(err error) bool {
	var nfe *attachment.NotFoundError
	return errors.As(err, &nfe)
}

// IsValidation checks if an error is a validation error.
func IsValidation(err error) bool {
	var ve *attachment.ValidationError
	return errors.As(err, &ve)
}

// --- Conversion helpers ---

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

// Ensure Store implements the service interfaces.
var (
	_ api.AttachmentService = (*Store)(nil)
	_ api.RulesetService    = (*Store)(nil)
	_ api.StatsService      = (*Store)(nil)
	_ api.EgressService     = (*Store)(nil)
	_ api.StatusService     = (*Store)(nil)
)
