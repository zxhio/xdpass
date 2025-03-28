package protos

import (
	"encoding/json"
	"fmt"
)

type Type int

const (
	TypeRedirect Type = iota + 1
	TypeFirewall
	TypeInterface
	TypeStats
)

var typeToStr = map[Type]string{
	TypeRedirect:  "redirect",
	TypeFirewall:  "firewall",
	TypeInterface: "interface",
	TypeStats:     "stats",
}

var strToType = make(map[string]Type)

func init() {
	for typ, str := range typeToStr {
		strToType[str] = typ
	}
}

func (t Type) String() string {
	return typeToStr[t]
}

func (t *Type) Set(s string) error {
	v, ok := strToType[s]
	if !ok {
		return fmt.Errorf("invalid type: %s", s)
	}
	*t = v
	return nil
}

func (t Type) MarshalJSON() ([]byte, error) {
	s, ok := typeToStr[t]
	if !ok {
		return nil, fmt.Errorf("invalid type: %d", t)
	}
	return json.Marshal(s)
}

func (t *Type) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	return t.Set(s)
}
