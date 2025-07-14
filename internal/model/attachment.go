package model

import (
	"time"

	"github.com/zxhio/xdpass/pkg/netaddr"
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
	// ProgramID   string        `json:"program_id"`
	// TODO: add xdp options
}

type IP struct {
	AttachmentName string             `json:"attachment_name"`
	Action         XDPAction          `json:"action"`
	IP             netaddr.IPv4Prefix `json:"ip"`
}
