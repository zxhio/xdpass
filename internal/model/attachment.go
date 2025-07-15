package model

import (
	"time"

	"github.com/zxhio/xdpass/pkg/netaddr"
	"github.com/zxhio/xdpass/pkg/netutil"
)

type XDPAction string

const (
	XDPActionPass     XDPAction = "pass"
	XDPActionRedirect XDPAction = "redirect"
)

type Attachment struct {
	Name        string        `json:"name"`
	Mode        string        `json:"mode"`
	Queues      []int         `json:"queues,omitempty"`
	Cores       []int         `json:"cores,omitempty"`
	PullTimeout time.Duration `json:"pull_timeout,omitempty"`
	BindFlags   uint16        `json:"bind_flags"`
	// ProgramID   string        `json:"program_id"`
}

type AttachmentStats struct {
	Name    string `json:"name"`
	QueueID uint32 `json:"queue_id"`
	netutil.Statistics
}

type IP struct {
	AttachmentName string             `json:"attachment_name"`
	Action         XDPAction          `json:"action"`
	IP             netaddr.IPv4Prefix `json:"ip"`
}
