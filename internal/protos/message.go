package protos

import (
	"encoding/json"
	"fmt"
)

type Type int

const (
	Type_Redirect Type = iota + 1
	Type_Filter
	Type_Interface
	Type_Stats
)

const (
	TypeStr_Redirect  = "redirect"
	TypeStr_Filter    = "filter"
	TypeStr_Interface = "interface"
	TypeStr_Stats     = "stats"
)

var typeLookup = map[string]Type{
	TypeStr_Redirect:  Type_Redirect,
	TypeStr_Filter:    Type_Filter,
	TypeStr_Interface: Type_Interface,
	TypeStr_Stats:     Type_Stats,
}

var typeStrLookup = map[Type]string{
	Type_Redirect:  TypeStr_Redirect,
	Type_Filter:    TypeStr_Filter,
	Type_Interface: TypeStr_Interface,
	Type_Stats:     TypeStr_Stats,
}

func (t Type) String() string {
	return typeStrLookup[t]
}

func (t *Type) Set(s string) error {
	*t = typeLookup[s]
	return nil
}

func (t Type) MarshalJSON() ([]byte, error) {
	s, ok := typeStrLookup[t]
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

	v, ok := typeLookup[s]
	if !ok {
		return fmt.Errorf("invalid type: %s", s)
	}
	*t = v
	return nil
}

type MessageReq struct {
	Type Type            `json:"type"`
	ID   string          `json:"id,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

type MessageResp struct {
	Status    int             `json:"status"`
	ID        string          `json:"id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Message   string          `json:"message,omitempty"`
	ErrorCode ErrorCode       `json:"error_code,omitempty"`
}

func MakeMessageReqData[T any](t Type, id string, v *T) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(MessageReq{Type: t, ID: id, Data: data})
}

func MakeMessageRespData[T any](status int, id string, v *T) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(MessageResp{Status: status, ID: id, Data: data})
}

func GetMessageRespValue[T any](data []byte) (*T, error) {
	var resp MessageResp
	err := json.Unmarshal(data, &resp)
	if err != nil {
		return nil, err
	}

	if resp.ErrorCode != 0 {
		return nil, fmt.Errorf("error code: %d, message: %s", resp.ErrorCode, resp.Message)
	}

	var v T
	err = json.Unmarshal(resp.Data, &v)
	if err != nil {
		return nil, err
	}
	return &v, nil
}
