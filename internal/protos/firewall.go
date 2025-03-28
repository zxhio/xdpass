package protos

import (
	"github.com/zxhio/xdpass/pkg/inet"
)

type FirewallReq struct {
	Operation Operation      `json:"operation"`
	Interface string         `json:"interface"`
	Keys      []inet.LPMIPv4 `json:"keys,omitempty"`
}

type FirewallResp struct {
	Interfaces []FirewallIPKeys `json:"interfaces,omitempty"`
}

type FirewallIPKeys struct {
	Interface string         `json:"interface"`
	Keys      []inet.LPMIPv4 `json:"keys,omitempty"`
}
