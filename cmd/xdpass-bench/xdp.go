package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/pkg/xdp"
	"golang.org/x/sys/unix"
)

type xdpTxBenchPool struct {
	idx        int
	benchmarks []*xdpTxBench
}

func newXDPTxBenchPool(ifaceName string, queueId int) (*xdpTxBenchPool, error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, errors.Wrap(err, "netlink.LinkByName")
	}
	logrus.WithFields(logrus.Fields{
		"name":   link.Attrs().Name,
		"index":  link.Attrs().Index,
		"num_tx": link.Attrs().NumTxQueues,
	}).Info("Found link")

	var pool xdpTxBenchPool
	if queueId != -1 {
		b, err := newXDPTxBench(ifaceName, uint32(queueId))
		if err != nil {
			return nil, err
		}
		pool.benchmarks = append(pool.benchmarks, b)
	} else {
		for id := 0; id < link.Attrs().NumTxQueues; id++ {
			rxQueuePath := fmt.Sprintf("/sys/class/net/%s/queues/tx-%d", ifaceName, id)
			_, err = os.Stat(rxQueuePath)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, errors.Wrap(err, "os.Stat")
			}

			b, err := newXDPTxBench(ifaceName, uint32(id))
			if err != nil {
				return nil, err
			}
			pool.benchmarks = append(pool.benchmarks, b)
		}
	}
	return &pool, nil
}

func (b *xdpTxBenchPool) benchmarkTx(bd *txBenchData) {
	b.benchmarks[b.idx%len(b.benchmarks)].benchmarkTx(bd)
	b.idx++
}

func (b *xdpTxBenchPool) waitTxDone(bd *txBenchData) {
	for _, bb := range b.benchmarks {
		for bb.standing != 0 {
			bb.complete(bd)
		}
		time.Sleep(time.Millisecond * 10)
	}
}

type xdpTxBench struct {
	*xdp.XDPSocket
	standing uint32
}

func newXDPTxBench(ifaceName string, queueId uint32) (*xdpTxBench, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, errors.Wrap(err, "net.InterfaceByName")
	}

	s, err := xdp.NewXDPSocket(uint32(iface.Index), queueId, xdp.WithXDPBindFlags(unix.XDP_FLAGS_SKB_MODE))
	if err != nil {
		return nil, err
	}
	logrus.WithFields(logrus.Fields{"fd": s.SocketFd(), "queue_id": queueId}).Info("New xdp socket")

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
