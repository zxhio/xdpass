package rule

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/zxhio/xdpass/pkg/netaddr"
)

func TestRule(t *testing.T) {
	r := Rule{
		Matchs: []Match{
			MatchIPv4PrefixDst{netaddr.IPv4Addr(127<<24 + 1), 8},
			MatchPortRangeDst{1, 1024},
			MatchMultiPortSrc{80, 443},
		},
		Target: TargetTCPSpoofSYNACK{},
	}

	data, err := json.Marshal(r)
	fmt.Println(string(data))
	t.Log(string(data), err)

	json.Unmarshal(data, &r)
	t.Logf("%+v", r.Matchs)
}
