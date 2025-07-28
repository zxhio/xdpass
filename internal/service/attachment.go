package service

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/internal/errcode"
	"github.com/zxhio/xdpass/internal/model"
	"github.com/zxhio/xdpass/internal/xdpprog"
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netaddr"
	"github.com/zxhio/xdpass/pkg/netutil"
	"github.com/zxhio/xdpass/pkg/utils"
	"github.com/zxhio/xdpass/pkg/xdp"
	"golang.org/x/sys/unix"
)

type AttachmentService struct {
	handler PacketHandler

	mu          *sync.RWMutex
	attachments []*Attachment
	passIPs     map[string][]netaddr.IPv4Prefix
	redirectIPs map[string][]netaddr.IPv4Prefix
}

func NewAttachmentService(h PacketHandler) (*AttachmentService, error) {
	return &AttachmentService{
		handler:     h,
		mu:          &sync.RWMutex{},
		passIPs:     make(map[string][]netaddr.IPv4Prefix),
		redirectIPs: make(map[string][]netaddr.IPv4Prefix),
	}, nil
}

func (s *AttachmentService) AddAttachment(a *model.Attachment, forceZeroCopy, forceCopy, noNeedWakeup bool) error {
	l := logrus.WithField("name", a.Name)
	l.WithFields(logrus.Fields{
		"mode":    a.Mode,
		"cores":   utils.SliceString(a.Cores),
		"queues":  utils.SliceString(a.Queues),
		"timeout": a.PullTimeout,
	}).Info("Adding attachment")

	if a.PullTimeout > 0 {
		a.PullTimeout = max(a.PullTimeout, time.Millisecond*10)
	}

	var opts []xdp.XDPOpt
	if forceZeroCopy {
		opts = append(opts, xdp.WithZeroCopy())
	} else if forceCopy {
		opts = append(opts, xdp.WithCopy())
	}
	if noNeedWakeup {
		opts = append(opts, xdp.WithNoNeedWakeup())
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	idx := slices.IndexFunc(s.attachments, func(att *Attachment) bool { return att.Name == a.Name })
	if idx != -1 {
		return errcode.New(errcode.CodeExist, "attachment: %s", a.Name)
	}

	attachment, err := NewAttachment(a, s.handler, opts...)
	if err != nil {
		return errcode.NewError(errcode.CodeInternal, err)
	}
	s.attachments = append(s.attachments, attachment)

	go attachment.Run(context.Background())

	l.Info("Added attachment")
	return nil
}

func (s *AttachmentService) DeleteAttachment(name string) error {
	logrus.WithField("name", name).Info("Deleting attachment")

	s.mu.Lock()
	defer s.mu.Unlock()

	idx := slices.IndexFunc(s.attachments, func(att *Attachment) bool { return att.Name == name })
	if idx == -1 {
		return errcode.New(errcode.CodeNotExist, "attachment: %s", name)
	}
	s.deleteAttachmentIP(s.attachments[idx])

	s.attachments[idx].Close()
	s.attachments = slices.Delete(s.attachments, idx, idx+1)

	logrus.WithField("name", name).Info("Deleted attachment")
	return nil
}

func (s *AttachmentService) QueryAttachment(name string) (*model.Attachment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idx := slices.IndexFunc(s.attachments, func(a *Attachment) bool { return a.Name == name })
	if idx == -1 {
		return nil, errcode.New(errcode.CodeNotExist, "attachment: %s", name)
	}
	return s.attachments[idx].Attachment, nil
}

func (s *AttachmentService) QueryAttachments(page, limit int) ([]*model.Attachment, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sls, total := utils.LimitPageSlice(s.attachments, page, limit)

	attachments := make([]*model.Attachment, 0, len(sls))
	for _, a := range s.attachments {
		attachments = append(attachments, a.Attachment)
	}
	return attachments, total, nil
}

func (s *AttachmentService) QueryAttachmentStats(name string) ([]model.AttachmentStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idx := slices.IndexFunc(s.attachments, func(a *Attachment) bool { return a.Name == name })
	if idx == -1 {
		return nil, errcode.New(errcode.CodeNotExist, "attachment: %s", name)
	}
	return s.attachments[idx].GetAllQueueStats(), nil
}

func (s *AttachmentService) AddIP(ips []*model.IP) error {
	for _, ip := range ips {
		s.mu.Lock()
		err := s.addIP(ip)
		s.mu.Unlock()

		if err != nil {
			return err
		}
	}
	return nil
}

func (s *AttachmentService) addIP(ip *model.IP) error {
	logrus.WithFields(logrus.Fields{"name": ip.AttachmentName, "action": ip.Action, "ip": ip.IP}).Info("Adding ip to attachment")

	idx := slices.IndexFunc(s.attachments, func(a *Attachment) bool { return a.Name == ip.AttachmentName })
	if idx == -1 {
		return errcode.New(errcode.CodeNotExist, "attachment: %s", ip.AttachmentName)
	}
	att := s.attachments[idx]

	switch ip.Action {
	case model.XDPActionPass:
		return s.checkIPAndAdd(ip, s.passIPs, att.Objects.PassLpmTrie)
	case model.XDPActionRedirect:
		return s.checkIPAndAdd(ip, s.redirectIPs, att.Objects.RedirectLpmTrie)
	default:
		return errcode.New(errcode.CodeInvalid, "action: %s", ip.Action)
	}
}

func (s *AttachmentService) checkIPAndAdd(ip *model.IP, ips map[string][]netaddr.IPv4Prefix, trie *ebpf.Map) error {
	if slices.Contains(ips[ip.AttachmentName], ip.IP) {
		return errcode.New(errcode.CodeExist, "ip: %s", ip.IP)
	}
	err := trie.Update(xdpprog.NewIPLpmKey(ip.IP), uint8(0), 0)
	if err != nil {
		return errcode.NewError(errcode.CodeInternal, err)
	}
	ips[ip.AttachmentName] = append(ips[ip.AttachmentName], ip.IP)
	logrus.WithFields(logrus.Fields{"name": ip.AttachmentName, "action": ip.Action, "ip": ip.IP}).Info("Added ip to attachment")

	return nil
}

func (s *AttachmentService) DeleteIP(ip *model.IP) error {
	logrus.WithFields(logrus.Fields{"name": ip.AttachmentName, "action": ip.Action, "ip": ip.IP}).Info("Deleting ip from attachment")

	s.mu.Lock()
	defer s.mu.Unlock()

	idx := slices.IndexFunc(s.attachments, func(a *Attachment) bool { return a.Name == ip.AttachmentName })
	if idx == -1 {
		return errcode.New(errcode.CodeNotExist, "attachment: %s", ip.AttachmentName)
	}

	switch ip.Action {
	case model.XDPActionPass:
		return s.deleteIP(ip, s.passIPs, s.attachments[idx].PassLpmTrie)
	case model.XDPActionRedirect:
		return s.deleteIP(ip, s.redirectIPs, s.attachments[idx].RedirectLpmTrie)
	default:
		return errcode.New(errcode.CodeInvalid, "action: %s", ip.Action)
	}
}

func (s *AttachmentService) deleteAttachmentIP(a *Attachment) error {
	del := func(ips map[string][]netaddr.IPv4Prefix, trie *ebpf.Map) {
		sls, ok := ips[a.Name]
		if !ok {
			return
		}

		for _, ip := range sls {
			trie.Delete(xdpprog.NewIPLpmKey(ip))
		}
		delete(ips, a.Name)
	}

	del(s.passIPs, a.PassLpmTrie)
	del(s.redirectIPs, a.RedirectLpmTrie)
	return nil
}

func (s *AttachmentService) deleteIP(ip *model.IP, ips map[string][]netaddr.IPv4Prefix, trie *ebpf.Map) error {
	err := trie.Delete(xdpprog.NewIPLpmKey(ip.IP))
	if err != nil {
		return errcode.NewError(errcode.CodeInternal, err)
	}
	idx := slices.Index(ips[ip.AttachmentName], ip.IP)
	if idx != -1 {
		ips[ip.AttachmentName] = slices.Delete(ips[ip.AttachmentName], idx, idx+1)
		logrus.WithFields(logrus.Fields{"name": ip.AttachmentName, "action": ip.Action, "ip": ip.IP}).Info("Deleted ip from attachment")
	}
	return nil
}

func (s *AttachmentService) QueryIP(attachmentName string, action model.XDPAction, page, limit int) ([]*model.IP, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idx := slices.IndexFunc(s.attachments, func(a *Attachment) bool { return a.Name == attachmentName })
	if idx == -1 {
		return nil, 0, errcode.New(errcode.CodeNotExist, "attachment: %s", attachmentName)
	}

	switch action {
	case model.XDPActionPass:
		return s.queryIP(s.passIPs[attachmentName], attachmentName, action, page, limit)
	case model.XDPActionRedirect:
		return s.queryIP(s.redirectIPs[attachmentName], attachmentName, action, page, limit)
	default:
		return nil, 0, errcode.New(errcode.CodeInvalid, "action: %s", action)
	}
}

func (s *AttachmentService) queryIP(ips []netaddr.IPv4Prefix, attachmentName string, action model.XDPAction, page, limit int) ([]*model.IP, int, error) {
	var (
		results []*model.IP
		total   int
	)

	data, total := utils.LimitPageSlice(ips, page, limit)
	for _, ip := range data {
		results = append(results, &model.IP{
			AttachmentName: attachmentName,
			Action:         action,
			IP:             ip,
		})
	}
	return results, total, nil
}

type Attachment struct {
	*model.Attachment
	*xdpprog.Objects
	handler PacketHandler

	mu      *sync.RWMutex
	xsks    []*xdp.XDPSocket
	closers utils.NamedClosers
	ctx     context.Context
	cancel  func()
	log     *logrus.Entry
}

func NewAttachment(a *model.Attachment, h PacketHandler, opts ...xdp.XDPOpt) (*Attachment, error) {
	l := logrus.WithField("name", a.Name)

	o := xdp.XDPDefaultOpts()
	for _, opt := range opts {
		opt(&o)
	}
	a.BindFlags = uint16(o.BindFlags)

	var m xdp.XDPAttachMode
	err := m.Set(a.Mode)
	if err != nil {
		return nil, fmt.Errorf("invalid attach mode: %s", a.Mode)
	}

	ifaceLink, err := netlink.LinkByName(a.Name)
	if err != nil {
		return nil, errors.Wrap(err, "netlink.LinkByName")
	}
	l.WithFields(logrus.Fields{
		"iface":  ifaceLink.Attrs().Name,
		"index":  ifaceLink.Attrs().Index,
		"num_rx": ifaceLink.Attrs().NumRxQueues,
		"num_tx": ifaceLink.Attrs().NumTxQueues,
	}).Info("Detected network link")

	objs, err := xdpprog.LoadObjects(nil)
	if err != nil {
		return nil, err
	}
	closers := utils.NamedClosers{{Name: "xdpprog.Objects", Close: objs.Close}}

	// Attach xdp program
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRedirectXskProg,
		Interface: ifaceLink.Attrs().Index,
		Flags:     link.XDPAttachFlags(m),
	})
	if err != nil {
		closers.Close(nil)
		return nil, errors.Wrap(err, "link.AttachXDP")
	}
	closers = append(closers, utils.NamedCloser{Name: "ebpf.Link", Close: xdpLink.Close})

	info, err := xdpLink.Info()
	if err != nil {
		l.WithError(err).Warn("Fail to get xdp link info")
	} else {
		l.WithFields(logrus.Fields{"id": info.ID, "type": info.Type, "prog": info.Program}).Info("Detected xdp link")
	}

	// Generate xdp socket per queue
	var queues []int
	if len(a.Queues) == 0 {
		queues, err = netutil.GetRxQueues(a.Name)
		if err != nil {
			return nil, err
		}
	} else {
		queues = a.Queues
	}
	a.Queues = queues
	l.WithField("rx", utils.SliceString(queues)).Info("Select netlink queues")

	var xsks []*xdp.XDPSocket
	for _, queueID := range queues {
		s, err := xdp.NewXDPSocket(uint32(ifaceLink.Attrs().Index), uint32(queueID), append(opts, xdp.WithFrameSize(xdp.UmemFrameSize2048))...)
		if err != nil {
			return nil, err
		}

		closers = append(closers, utils.NamedCloser{Name: fmt.Sprintf("xdp.XDPSocket(fd:%d queue:%d)", s.SocketFD(), queueID), Close: s.Close})
		xsks = append(xsks, s)
		l.WithFields(logrus.Fields{"fd": s.SocketFD(), "queue_id": queueID}).Info("New xdp socket")

		// Update xsk map
		// Note: xsk map not support lookup element,
		//       See kernel tree net/xdp/xdpmap.c *xsk_map_lookup_elem_sys_only()* implement
		err = objs.XskMap.Update(uint32(queueID), uint32(s.SocketFD()), 0)
		if err != nil {
			closers.Close(nil)
			return nil, errors.Wrap(err, "XskMap.Update")
		}
		l.WithFields(logrus.Fields{"k": queueID, "v": s.SocketFD()}).Info("Update xsk map")
	}

	cores := a.Cores[:min(len(xsks), len(a.Cores))]
	if len(cores) == 0 {
		cores = []int{-1}
	}
	a.Cores = cores
	l.WithField("cores", utils.SliceString(a.Cores)).Info("Select cpu")

	ctx, cancel := context.WithCancel(context.Background())
	return &Attachment{
		Attachment: a,
		Objects:    objs,
		handler:    h,
		xsks:       xsks,
		closers:    closers,
		mu:         &sync.RWMutex{},
		ctx:        ctx,
		cancel:     cancel,
		log:        l,
	}, nil
}

func (a *Attachment) Close() error {
	a.cancel()
	return nil
}

type xskGroup struct {
	xsks []*xdp.XDPSocket
	core int
	fds  []unix.PollFd
}

func (a *Attachment) Run(ctx context.Context) error {
	defer func() {
		a.closers.Close(&utils.CloseOpt{
			ReverseOrder: true,
			Output:       a.log.Info,
			ErrorOutput:  a.log.Error,
		})
		a.cancel()
	}()

	done := false
	go func() {
		select {
		case <-a.ctx.Done():
		case <-ctx.Done():
		}
		done = true
	}()

	var xskGroups []*xskGroup
	for _, core := range a.Cores {
		xskGroups = append(xskGroups, &xskGroup{core: core})
	}
	for k, xsk := range a.xsks {
		xskGroups[k%len(xskGroups)].xsks = append(xskGroups[k%len(xskGroups)].xsks, xsk)
		xskGroups[k%len(xskGroups)].fds = append(xskGroups[k%len(xskGroups)].fds, unix.PollFd{Fd: int32(xsk.SocketFD()), Events: unix.POLLIN})
	}

	wg := sync.WaitGroup{}
	wg.Add(len(xskGroups))

	for _, xg := range xskGroups {
		go func(g *xskGroup) {
			defer wg.Done()

			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			l := a.log.WithField("tid", unix.Gettid())
			if g.core != -1 {
				setAffinityCPU(g.core)
				l = l.WithField("core", g.core)
			}
			var fds []int
			for _, x := range g.xsks {
				fds = append(fds, x.SocketFD())
			}
			l.WithField("sockets", utils.SliceString(fds)).Info("Run xdp rx loop")

			pkt := fastpkt.Packet{}
			tmpTxData := make([]byte, xdp.UmemDefaultFrameSize)
			for !done {
				err := a.waitPoll(g.fds)
				if err != nil {
					continue
				}
				for _, xsk := range g.xsks {
					pkt.Clear()
					xsk.HandlePackets(func(b []byte) []byte {
						pkt.TxData = tmpTxData[:0]
						err := pkt.DecodeFromData(b)
						if err != nil {
							return nil
						}
						a.handler.OnPacket(&pkt)
						return pkt.TxData
					})
				}
			}
		}(xg)
	}
	wg.Wait()

	return nil
}

func (a *Attachment) waitPoll(fds []unix.PollFd) error {
	if a.PullTimeout == 0 {
		return nil
	}

	_, err := unix.Poll(fds, int(a.PullTimeout.Milliseconds()))
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			return nil
		}
		return errors.Wrap(err, "unix.Poll")
	}
	return nil
}

func (x *Attachment) GetAllQueueStats() []model.AttachmentStats {
	stats := make([]model.AttachmentStats, 0, len(x.xsks))
	for _, xsk := range x.xsks {
		stats = append(stats, model.AttachmentStats{
			Name:       x.Name,
			QueueID:    xsk.QueueID(),
			Statistics: xsk.Stats(),
		})
	}
	return stats
}

func setAffinityCPU(cpu int) error {
	var s unix.CPUSet
	s.Zero()
	s.Set(cpu)
	return unix.SchedSetaffinity(0, &s)
}
