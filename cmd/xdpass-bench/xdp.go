package main

import (
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/pkg/xdp"
	"golang.org/x/sys/unix"
)

type xdpTxBench struct {
	*xdp.XDPSocket
	standing uint32
}

func newXDPTxBench(ifaceName string) (*xdpTxBench, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, errors.Wrap(err, "net.InterfaceByName")
	}

	s, err := xdp.NewXDPSocket(uint32(iface.Index), 0, xdp.WithXDPBindFlags(unix.XDP_FLAGS_SKB_MODE))
	if err != nil {
		return nil, err
	}
	logrus.WithField("fd", s.SocketFd()).Info("New xdp socket")

	return &xdpTxBench{XDPSocket: s}, nil
}

func (b *xdpTxBench) benchmarkTx(bd *txBenchData) {
	var idx uint32
	for b.Tx.Reserve(bd.batchSize, &idx) < bd.batchSize {
		b.complete(bd)
		if *bd.done {
			return
		}
	}

	for i := uint32(0); i < bd.batchSize; i++ {
		desc := b.Tx.GetDesc(idx + i)
		desc.Len = uint32(len(bd.data))
		desc.Addr = b.AllocUmemFrame()
		copy(b.Umem.GetData(desc), bd.data)
	}

	b.standing += bd.batchSize
	b.Tx.Submit(bd.batchSize)
	b.complete(bd)
}

func (b *xdpTxBench) complete(bd *txBenchData) {
	if b.standing == 0 {
		return
	}

	err := unix.Sendto(b.SocketFd(), nil, unix.MSG_DONTWAIT, nil)
	if err != nil {
		bd.stats.sendFailCount++
	}
	bd.stats.sendCount++

	var (
		idx       uint32
		completed uint32
	)
	completed = b.Umem.Comp.Peek(bd.batchSize, &idx)
	if completed == 0 {
		return
	}
	for i := uint32(0); i < completed; i++ {
		bd.stats.txPackets++
		bd.stats.txBytes += len(bd.data)
		b.FreeUmemFrame(*b.Umem.Comp.GetAddr(idx + i))
	}
	b.Umem.Comp.Release(completed)
	b.standing -= completed
}

func (b *xdpTxBench) waitTxDone(bd *txBenchData) {
	for b.standing != 0 {
		b.complete(bd)
		time.Sleep(time.Millisecond * 10)
	}
}
