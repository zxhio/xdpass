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

var redirectTypeToStr = map[RedirectType]string{
	RedirectTypeDump:   "dump",
	RedirectTypeRemote: "remote",
	RedirectTypeSpoof:  "spoof",
	RedirectTypeTuntap: "tuntap",
}

var strToRedirectType = make(map[string]RedirectType)

func init() {
	for matchType, str := range redirectTypeToStr {
		strToRedirectType[str] = matchType
	}
}

func (t RedirectType) String() string {
	return redirectTypeToStr[t]
}

func (t *RedirectType) Set(s string) error {
	v, ok := strToRedirectType[s]
	if !ok {
		return fmt.Errorf("invalid redirect type: %s", s)
	}
	*t = v
	return nil
}

func (t RedirectType) MarshalJSON() ([]byte, error) {
	s, ok := redirectTypeToStr[t]
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

type TuntapDevice struct {
	Name string             `json:"name"`
	Mode netlink.TuntapMode `json:"mode,omitempty"`
}
