package handle

import (
	"encoding/json"

	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/fastpkt"
)

type RedirectHandle interface {
	RedirectType() protos.RedirectType
	HandlePacket(pkt *fastpkt.Packet)
	Close() error
}

func ResponseRedirectValue[T any](client *commands.MessageClient, v *T) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}
	resp := protos.MessageResp{Data: raw, ErrorCode: 0}
	return commands.Response(client, &resp)
}
