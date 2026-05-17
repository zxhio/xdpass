package api

import "context"

// StatusService provides agent health and status information.
type StatusService interface {
	Status(ctx context.Context) (StatusResponse, error)
}

// AttachmentService manages XDP attachment runtime state.
type AttachmentService interface {
	ListAttachments(ctx context.Context) ([]AttachmentResponse, error)
	GetAttachment(ctx context.Context, ifIndex uint32) (AttachmentResponse, error)
	CreateAttachment(ctx context.Context, req AttachmentRequest) (AttachmentResponse, error)
	DryRunAttachment(ctx context.Context, req AttachmentRequest) (AttachmentResponse, error)
	PatchAttachment(ctx context.Context, ifIndex uint32, enabled bool) (AttachmentResponse, error)
	DeleteAttachment(ctx context.Context, ifIndex uint32) error
}

// RulesetService manages the runtime ruleset.
type RulesetService interface {
	GetRuleset(ctx context.Context) (RulesetResponse, error)
	ReplaceRuleset(ctx context.Context, rules []RuleResponse) (RulesetResponse, error)
	DryRunRuleset(ctx context.Context, rules []RuleResponse) (RulesetResponse, error)
	DeleteRuleset(ctx context.Context) error
}

// StatsService provides runtime statistics.
type StatsService interface {
	GetStats(ctx context.Context) (StatsResponse, error)
}

// EgressService manages response egress configuration.
type EgressService interface {
	GetEgress(ctx context.Context) (EgressResponse, error)
	ReplaceEgress(ctx context.Context, ifIndex uint32, ifName, vlanMode string) (EgressResponse, error)
	DeleteEgress(ctx context.Context) error
}

// DispatchService manages dispatch configuration.
type DispatchService interface {
	GetDispatch(ctx context.Context) (DispatchResponse, error)
	ReplaceDispatch(ctx context.Context, req PutDispatchRequest) (DispatchResponse, error)
	DeleteDispatch(ctx context.Context) error
}
