package netq

import (
	"context"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/internal/config"
	"github.com/zxhio/xdpass/internal/handles"
	"github.com/zxhio/xdpass/internal/stats"
	"github.com/zxhio/xdpass/pkg/utils"
	"github.com/zxhio/xdpass/pkg/xdp"
	"github.com/zxhio/xdpass/pkg/xdpprog"
	"golang.org/x/sys/unix"
)

type RxOpt struct {
	IfaceName    string
	QueueID      int
	XDPFlags     config.XDPFlagsMode
	PollTimewait int
}

type RxDataDispatcher struct {
	*RxOpt

	*xdp.XDPSocket
	*xdpprog.Objects
	handlers  []handles.DataProcessor
	ipLpmKeys map[xdpprog.IPLpmKey]struct{}
	mu        sync.Mutex
	closers   utils.NamedClosers
}

func NewRxDataDispatcher(opt *RxOpt, handlers []handles.DataProcessor) (*RxDataDispatcher, error) {
	ifaceLink, err := netlink.LinkByName(opt.IfaceName)
	if err != nil {
		return nil, errors.Wrap(err, "netlink.LinkByName")
	}
	logrus.WithFields(logrus.Fields{
		"name": ifaceLink.Attrs().Name, "index": ifaceLink.Attrs().Index,
		"num_RxWorker": ifaceLink.Attrs().NumRxQueues, "num_tx": ifaceLink.Attrs().NumTxQueues,
	}).Info("Detected link")

	var closers utils.NamedClosers

	s, err := xdp.NewXDPSocket(uint32(ifaceLink.Attrs().Index), uint32(opt.QueueID), xdp.WithXDPBindFlags(unix.XDP_FLAGS_SKB_MODE))
	if err != nil {
		return nil, err
	}
	closers = append(closers, utils.NamedCloser{Name: "xdp.XDPSocket", Close: s.Close})
	logrus.WithFields(logrus.Fields{"fd": s.SocketFd(), "queue_id": opt.QueueID}).Info("New xdp socket")

	objs, err := xdpprog.LoadObjects(nil)
	if err != nil {
		closers.Close(nil)
		return nil, err
	}
	closers = append(closers, utils.NamedCloser{Name: "xdpprog.Objects", Close: objs.Close})

	// Attach xdp program
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRedirectXskProg,
		Interface: ifaceLink.Attrs().Index,
		Flags:     link.XDPAttachFlags(opt.XDPFlags),
	})
	if err != nil {
		closers.Close(nil)
		return nil, errors.Wrap(err, "link.AttachXDP")
	}
	closers = append(closers, utils.NamedCloser{Name: "ebpflink.Link", Close: xdpLink.Close})
	logrus.WithField("flags", opt.XDPFlags).Info("Attached xdp prog")

	info, err := xdpLink.Info()
	if err != nil {
		logrus.WithError(err).Warn("Fail to get xdp link info")
	} else {
		logrus.WithFields(logrus.Fields{"id": info.ID, "type": info.Type, "prog": info.Program}).Info("Attached xdp objects")
	}

	return &RxDataDispatcher{
		RxOpt:     opt,
		XDPSocket: s,
		Objects:   objs,
		handlers:  handlers,
		ipLpmKeys: make(map[xdpprog.IPLpmKey]struct{}),
		closers:   closers,
	}, nil
}

func (p *RxDataDispatcher) AddIPKey(key xdpprog.IPLpmKey) error {
	logrus.WithField("key", key).Info("Add ip lpm")

	p.mu.Lock()
	defer p.mu.Unlock()

	err := p.IpLpmTrie.Update(&key, uint8(0), 0)
	if err != nil {
		return err
	}
	p.ipLpmKeys[key] = struct{}{}
	return nil
}

func (p *RxDataDispatcher) DelIPKey(key xdpprog.IPLpmKey) error {
	logrus.WithField("key", key).Info("Delete ip lpm")

	p.mu.Lock()
	defer p.mu.Unlock()

	err := p.IpLpmTrie.Delete(&key)
	if err != nil {
		return err
	}
	delete(p.ipLpmKeys, key)
	return nil
}

func (p *RxDataDispatcher) Run(ctx context.Context) error {
	// Update xsk map
	err := p.XskMap.Update(uint32(p.QueueID), uint32(p.SocketFd()), 0)
	if err != nil {
		return errors.Wrap(err, "XskMap.Update")
	}
	logrus.WithFields(logrus.Fields{"k": p.QueueID, "v": p.SocketFd()}).Info("Update xsk map")

	var (
		done bool
		idx  uint32
		n    uint32
		stat stats.Statistics
	)

	go func() {
		<-ctx.Done()
		done = true
	}()

	for !done {
		if p.PollTimewait > 0 {
			_, err := unix.Poll([]unix.PollFd{{Fd: int32(p.SocketFd()), Events: unix.POLLIN}}, p.PollTimewait)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				return errors.Wrap(err, "unix.Poll")
			}
		}

		stuffFillQ(p.XDPSocket)

		n = p.Rx.Peek(64, &idx)
		if n == 0 {
			continue
		}

		for i := uint32(0); i < n; i++ {
			desc := p.Rx.GetDesc(idx)

			stat.Bytes += uint64(desc.Len)
			stat.Packets++

			data := p.Umem.GetData(desc)
			for _, h := range p.handlers {
				h.ProcessData(data)
			}

			p.FreeUmemFrame(desc.Addr)
		}

		p.Rx.Release(n)
	}

	return nil
}

func (p *RxDataDispatcher) Stop() error {
	p.closers.Close(&utils.CloseOpt{ReverseOrder: true, Output: logrus.Debug, ErrorOutput: logrus.Error})
	return nil
}

func stuffFillQ(x *xdp.XDPSocket) {
	frames := x.Umem.Fill.Free(x.FreeUmemFrames())
	if frames == 0 {
		return
	}

	var idx uint32
	x.Umem.Fill.Reserve(frames, &idx)

	for i := uint32(0); i < frames; i++ {
		*x.Umem.Fill.GetAddr(idx) = x.AllocUmemFrame()
	}
	x.Umem.Fill.Submit(frames)
}
