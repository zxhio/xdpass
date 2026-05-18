package attachment

import (
	"fmt"

	"xdpass/internal/api"
	"xdpass/internal/xsk"
)

// XSKAfterCreateFunc is called after an attachment is created with XSK enabled.
// It should start XSK sockets and response workers.
type XSKAfterCreateFunc func(att *Attachment, maps MapAccessor) error

// XSKAfterPatchFunc is called after PatchEnabled toggles an attachment.
// enabled=true means the attachment was just enabled; false means disabled.
type XSKAfterPatchFunc func(att *Attachment, maps MapAccessor, enabled bool) error

// XSKPreDeleteFunc is called before an attachment is deleted.
type XSKPreDeleteFunc func(ifIndex uint32, maps MapAccessor)

// EventAfterCreateFunc is called after an attachment is created.
// It should start the event ringbuf reader. Return an error to rollback.
type EventAfterCreateFunc func(att *Attachment, maps MapAccessor) error

// EventAfterPatchFunc is called after PatchEnabled toggles an attachment.
// enabled=true means the attachment was just enabled; false means disabled.
type EventAfterPatchFunc func(att *Attachment, maps MapAccessor, enabled bool)

// EventPreDeleteFunc is called before an attachment is deleted.
type EventPreDeleteFunc func(ifIndex uint32, maps MapAccessor)

// Request holds the attachment creation parameters.
type Request struct {
	IfIndex     uint32
	AttachMode  string
	MissVerdict string
	Channels    *ChannelsConfig
	XSK         *XSKConfig
}

// ChannelsConfig holds RX queue channel configuration.
type ChannelsConfig struct {
	RxQueueCount    uint32
	MaxRxQueueCount uint32
}

// XSKConfig holds XSK configuration.
type XSKConfig struct {
	Enabled bool
	Queues  []uint32
	UMEM    xsk.Options
}

// Attachment holds the runtime attachment state.
type Attachment struct {
	IfIndex     uint32
	AttachMode  string
	Enabled     bool
	MissVerdict string
	Channels    ChannelsConfig
	XSK         XSKConfig
	ProgramID   uint32
	MapSetID    string
}

// ToAPIResponse converts an Attachment to an API response.
func (a *Attachment) ToAPIResponse() api.AttachmentResponse {
	channels := api.ChannelsResponse{
		RxQueueCount:    a.Channels.RxQueueCount,
		MaxRxQueueCount: a.Channels.MaxRxQueueCount,
	}

	var xsk api.XSKResponse
	if a.XSK.Enabled {
		queues := make([]uint32, len(a.XSK.Queues))
		copy(queues, a.XSK.Queues)
		xsk = api.XSKResponse{
			Enabled: true,
			Queues:  queues,
			UMEM:    umemToAPI(a.XSK.UMEM),
		}
	} else {
		xsk = api.XSKResponse{Enabled: false}
	}

	return api.AttachmentResponse{
		IfIndex:     a.IfIndex,
		AttachMode:  a.AttachMode,
		Enabled:     a.Enabled,
		MissVerdict: a.MissVerdict,
		Channels:    channels,
		XSK:         xsk,
		Runtime: api.RuntimeResponse{
			ProgramID: a.ProgramID,
			MapSetID:  a.MapSetID,
		},
	}
}

// ConflictError indicates a duplicate ifindex.
type ConflictError struct {
	IfIndex uint32
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("attachment ifindex=%d already exists", e.IfIndex)
}

// NotFoundError indicates a missing attachment.
type NotFoundError struct {
	IfIndex uint32
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("attachment ifindex=%d not found", e.IfIndex)
}

// ValidationError indicates invalid attachment parameters.
type ValidationError struct {
	Detail string
}

func (e *ValidationError) Error() string {
	return e.Detail
}

func umemToAPI(opts xsk.Options) *api.UMEMResponse {
	return &api.UMEMResponse{
		FrameSize:          opts.FrameSize,
		FrameCount:         opts.FrameCount,
		FillRingSize:       opts.FillRingSize,
		CompletionRingSize: opts.CompletionRingSize,
		RXRingSize:         opts.RXRingSize,
		TXRingSize:         opts.TXRingSize,
		TXFrameReserve:     opts.TXFrameReserve,
	}
}
