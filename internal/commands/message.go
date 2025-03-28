package commands

import (
	"encoding/json"
	"fmt"

	"github.com/zxhio/xdpass/internal/protos"
)

type MessageReq struct {
	Type protos.Type     `json:"type"`
	ID   string          `json:"id,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

type MessageResp struct {
	Status    int              `json:"status"`
	ID        string           `json:"id,omitempty"`
	Data      json.RawMessage  `json:"data,omitempty"`
	Message   string           `json:"message,omitempty"`
	ErrorCode protos.ErrorCode `json:"error_code,omitempty"`
}

func MakeMessageReqData[T any](t protos.Type, id string, v *T) ([]byte, error) {
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

type Operation int

const (
	OperationNop Operation = iota
	OperationAdd
	OperationDel
	OperationList
	OperationCustom
)

func (o Operation) String() string {
	switch o {
	case OperationNop:
		return "nop"
	case OperationAdd:
		return "add"
	case OperationDel:
		return "del"
	case OperationList:
		return "list"
	case OperationCustom:
		return "custom"
	}
	return fmt.Sprintf("custom+%d", o-OperationCustom)
}
