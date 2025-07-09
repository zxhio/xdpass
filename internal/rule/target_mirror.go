package rule

import (
	"fmt"

	"github.com/zxhio/xdpass/pkg/fastpkt"
)

type MirrorStdout struct{}

func (MirrorStdout) TargetType() TargetType     { return TargetTypeMirrorStdout }
func (MirrorStdout) MatchTypes() []MatchType    { return []MatchType{} }
func (t MirrorStdout) Compare(other Target) int { return CompareTargetType(t, other) }
func (MirrorStdout) Execute(pkt *fastpkt.Packet) error {
	fmt.Println(fastpkt.Format(pkt.RxData, fastpkt.WithFormatEthernet()))
	return nil
}

type MirrorTap struct{}

func (MirrorTap) TargetType() TargetType     { return TargetTypeMirrorTap }
func (MirrorTap) MatchTypes() []MatchType    { return []MatchType{} }
func (t MirrorTap) Compare(other Target) int { return CompareTargetType(t, other) }
func (MirrorTap) Execute(pkt *fastpkt.Packet) error {
	// TODO:
	return nil
}
