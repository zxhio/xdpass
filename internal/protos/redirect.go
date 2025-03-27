package protos

import (
	"encoding/json"
	"fmt"

	"github.com/vishvananda/netlink"
)

type RedirectType int

const (
	RedirectTypeDump RedirectType = iota + 1
	RedirectTypeRemote
	RedirectTypeSpoof
	RedirectTypeTuntap
)

const (
	redirectTypeStrDump   = "dump"
	redirectTypeStrRemote = "remote"
	redirectTypeStrSpoof  = "spoof"
	redirectTypeStrTuntap = "tuntap"
)

var redirectTypeStrLookup = map[RedirectType]string{
	RedirectTypeDump:   redirectTypeStrDump,
	RedirectTypeRemote: redirectTypeStrRemote,
	RedirectTypeSpoof:  redirectTypeStrSpoof,
	RedirectTypeTuntap: redirectTypeStrTuntap,
}

var redirectTypeLookup = map[string]RedirectType{
	redirectTypeStrDump:   RedirectTypeDump,
	redirectTypeStrRemote: RedirectTypeRemote,
	redirectTypeStrSpoof:  RedirectTypeSpoof,
	redirectTypeStrTuntap: RedirectTypeTuntap,
}

func (t RedirectType) String() string {
	return redirectTypeStrLookup[t]
}

func (t *RedirectType) Set(s string) error {
	v, ok := redirectTypeLookup[s]
	if !ok {
		return fmt.Errorf("invalid redirect type: %s", s)
	}
	*t = v
	return nil
}

func (t RedirectType) MarshalJSON() ([]byte, error) {
	s, ok := redirectTypeStrLookup[t]
	if !ok {
		return nil, fmt.Errorf("invalid redirect type %d", t)
	}
	return json.Marshal(s)
}

func (t *RedirectType) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	return t.Set(s)
}

type RedirectReq struct {
	RedirectType RedirectType    `json:"redirect_type"`
	RedirectData json.RawMessage `json:"redirect_data"`
}

type DumpReq struct {
	Interface string `json:"interface,omitempty"`
}

// Remote
// TODO: add req/resp

// Spoof

// Tun

type TuntapReq struct {
	Operation Operation      `json:"operation"`
	Interface string         `json:"interface,omitempty"`
	Devices   []TuntapDevice `json:"devices,omitempty"`
}

type TuntapDevice struct {
	Name string             `json:"name"`
	Mode netlink.TuntapMode `json:"mode,omitempty"`
}

type TuntapResp struct {
	Interfaces []TuntapInterfaceDevices `json:"interfaces,omitempty"`
}

type TuntapInterfaceDevices struct {
	Interface string         `json:"interface"`
	Devices   []TuntapDevice `json:"devices"`
}
