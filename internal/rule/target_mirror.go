package rule

import (
	"fmt"

	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/pkg/fastpkt"
)

type MirrorStdout struct{}

func (MirrorStdout) TargetType() TargetType     { return TargetTypeMirrorStdout }
func (MirrorStdout) MatchTypes() []MatchType    { return []MatchType{} }
func (t MirrorStdout) Compare(other Target) int { return CompareTargetType(t, other) }
func (MirrorStdout) Open() error                { return nil }
func (MirrorStdout) Execute(pkt *fastpkt.Packet) error {
	fmt.Println(fastpkt.Format(pkt.RxData, fastpkt.WithFormatEthernet()))
	if len(pkt.TxData) != 0 {
		fmt.Println(fastpkt.Format(pkt.TxData, fastpkt.WithFormatEthernet()))
	}
	return nil
}
func (MirrorStdout) Close() error { return nil }

type MirrorTap struct {
	Name string `json:"name"`
	tap  *netlink.Tuntap
}

func (MirrorTap) TargetType() TargetType      { return TargetTypeMirrorTap }
func (MirrorTap) MatchTypes() []MatchType     { return []MatchType{} }
func (t *MirrorTap) Compare(other Target) int { return CompareTargetType(t, other) }

func (t *MirrorTap) Open() error {
	t.tap = &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: t.Name},
		Mode:      netlink.TUNTAP_MODE_TAP,
		Flags:     netlink.TUNTAP_NO_PI | netlink.TUNTAP_ONE_QUEUE,
		Queues:    1,
	}
	if err := netlink.LinkAdd(t.tap); err != nil {
		return err
	}
	return netlink.LinkSetUp(t.tap)
}

func (t *MirrorTap) Execute(pkt *fastpkt.Packet) error {
	if t.tap == nil || len(t.tap.Fds) == 0 {
		return nil
	}
	_, err := t.tap.Fds[0].Write(pkt.RxData)
	if err != nil {
		return err
	}
	if len(pkt.TxData) != 0 {
		_, err = t.tap.Fds[0].Write(pkt.TxData)
	}
	return err
}

func (t *MirrorTap) Close() error {
	if t.tap == nil {
		return nil
	}
	for _, f := range t.tap.Fds {
		f.Close()
	}
	return netlink.LinkSetDown(t.tap)
}
