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

type xdpTxBenchmark struct {
	*xdp.XDPSocket
	standing uint32
}

func newXDPTxBenchmarks(ifaceName string, queueId int) ([]txBenchmark, error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, errors.Wrap(err, "netlink.LinkByName")
	}
	logrus.WithFields(logrus.Fields{
		"name":   link.Attrs().Name,
		"index":  link.Attrs().Index,
		"num_tx": link.Attrs().NumTxQueues,
	}).Info("Found link")

	var benchmarks []txBenchmark
	if queueId != -1 {
		b, err := newXDPTxBenchmark(ifaceName, uint32(queueId))
		if err != nil {
			return nil, err
		}
		benchmarks = append(benchmarks, b)
	} else {
		for id := 0; id < link.Attrs().NumTxQueues; id++ {
			txQueuePath := fmt.Sprintf("/sys/class/net/%s/queues/tx-%d", ifaceName, id)
			_, err = os.Stat(txQueuePath)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, errors.Wrap(err, "os.Stat")
			}

			b, err := newXDPTxBenchmark(ifaceName, uint32(id))
			if err != nil {
				return nil, err
			}
			benchmarks = append(benchmarks, b)
		}
	}
	return benchmarks, nil
}

func newXDPTxBenchmark(ifaceName string, queueId uint32) (*xdpTxBenchmark, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, errors.Wrap(err, "net.InterfaceByName")
	}

	// For compatibility reasons, use SKB mode.
	s, err := xdp.NewXDPSocket(uint32(iface.Index), queueId, xdp.WithXDPBindFlags(unix.XDP_FLAGS_SKB_MODE))
	if err != nil {
		return nil, err
	}
	logrus.WithFields(logrus.Fields{"fd": s.SocketFd(), "queue_id": queueId}).Info("New xdp socket")

	return &xdpTxBenchmark{XDPSocket: s}, nil
}

func (b *xdpTxBenchmark) runBatch(bd *txBenchmarkData) {
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

func (b *xdpTxBenchmark) complete(bd *txBenchmarkData) {
	if b.standing == 0 {
		return
	}

	err := unix.Sendto(b.SocketFd(), nil, unix.MSG_DONTWAIT, nil)
	if err != nil {
		bd.stat.IOFailCount++
	}
	bd.stat.IOCount++

	var (
		idx       uint32
		completed uint32
	)
	completed = b.Umem.Comp.Peek(bd.batchSize, &idx)
	if completed == 0 {
		return
	}
	for i := uint32(0); i < completed; i++ {
		bd.stat.Packets++
		bd.stat.Bytes += uint64(len(bd.data))
		b.FreeUmemFrame(*b.Umem.Comp.GetAddr(idx + i))
	}
	b.Umem.Comp.Release(completed)
	b.standing -= completed
}

func (b *xdpTxBenchmark) wait(bd *txBenchmarkData) {
	for b.standing != 0 {
		b.complete(bd)
		time.Sleep(time.Millisecond * 10)
	}
}
