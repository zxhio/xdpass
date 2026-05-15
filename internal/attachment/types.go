package attachment

import (
	"fmt"

	"xdpass/internal/api"
)

// XSKAfterCreateFunc is called after an attachment is created with XSK enabled.
// It should start XSK sockets and response workers.
type XSKAfterCreateFunc func(att *Attachment, maps MapAccessor) error

// XSKAfterPatchFunc is called after PatchEnabled toggles an attachment.
// enabled=true means the attachment was just enabled; false means disabled.
type XSKAfterPatchFunc func(att *Attachment, maps MapAccessor, enabled bool) error

// XSKPreDeleteFunc is called before an attachment is deleted.
type XSKPreDeleteFunc func(ifIndex uint32)

// Request holds the attachment creation parameters.
type Request struct {
	IfIndex     uint32
	IfName      string
	AttachMode  string
	MissVerdict string
	Channels    *ChannelsConfig
	XSK         *XSKConfig
}

// ChannelsConfig holds RX queue channel configuration.
type ChannelsConfig struct {
	RxQueueCount uint32
}

// XSKConfig holds XSK configuration.
type XSKConfig struct {
	Enabled bool
	Queues  []uint32
}

// Attachment holds the runtime attachment state.
type Attachment struct {
	IfIndex     uint32
	IfName      string
	AttachMode  string
	Enabled     bool
	MissVerdict string
	Channels    ChannelsConfig
	XSK         XSKConfig
}

// ToAPIResponse converts an Attachment to an API response.
func (a *Attachment) ToAPIResponse() api.AttachmentResponse {
	channels := api.ChannelsResponse{
		RxQueueCount: a.Channels.RxQueueCount,
	}

	var xsk api.XSKResponse
	if a.XSK.Enabled {
		queues := make([]uint32, len(a.XSK.Queues))
		copy(queues, a.XSK.Queues)
		xsk = api.XSKResponse{Enabled: true, Queues: queues}
	} else {
		xsk = api.XSKResponse{Enabled: false}
	}

	return api.AttachmentResponse{
		IfIndex:     a.IfIndex,
		IfName:      a.IfName,
		AttachMode:  a.AttachMode,
		Enabled:     a.Enabled,
		MissVerdict: a.MissVerdict,
		Channels:    channels,
		XSK:         xsk,
		Runtime:     api.RuntimeResponse{},
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
