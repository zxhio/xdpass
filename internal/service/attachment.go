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

func (s *AttachmentService) AddAttachment(a *model.Attachment) error {
	if a.PullTimeout > 0 {
		a.PullTimeout = max(a.PullTimeout, time.Millisecond*10)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	idx := slices.IndexFunc(s.attachments, func(att *Attachment) bool { return att.Name == a.Name })
	if idx != -1 {
		return fmt.Errorf("exist attachment: %s", a.Name)
	}

	attachment, err := NewAttachment(a, s.handler)
	if err != nil {
		return err
	}
	s.attachments = append(s.attachments, attachment)

	go attachment.Run()
	return nil
}

func (s *AttachmentService) DeleteAttachment(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := slices.IndexFunc(s.attachments, func(att *Attachment) bool { return att.Name == name })
	if idx == -1 {
		return fmt.Errorf("no such attachment: %s", name)
	}
	s.attachments[idx].Close()
	s.attachments = slices.Delete(s.attachments, idx, idx+1)
	return nil
}

func (s *AttachmentService) QueryAttachment(name string) (*model.Attachment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idx := slices.IndexFunc(s.attachments, func(a *Attachment) bool { return a.Name == name })
	if idx == -1 {
		return nil, fmt.Errorf("no such attachment: %s", name)
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

func (s *AttachmentService) AddIP(ips []*model.IP) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ip := range ips {
		err := s.addIP(ip)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *AttachmentService) addIP(ip *model.IP) error {
	if ip.Action != model.XDPActionPass && ip.Action != model.XDPActionRedirect {
		return fmt.Errorf("invalid xdp action: %s", ip.Action)
	}

	var attachments []*Attachment
	if ip.AttachmentName == "" {
		attachments = s.attachments
	} else {
		idx := slices.IndexFunc(s.attachments, func(a *Attachment) bool { return a.Name == ip.AttachmentName })
		if idx == -1 {
			return fmt.Errorf("no such attachment: %s", ip.AttachmentName)
		}
		attachments = []*Attachment{s.attachments[idx]}
	}

	for _, a := range attachments {
		var err error
		switch ip.Action {
		case model.XDPActionPass:
			if !slices.Contains(s.passIPs[a.Attachment.Name], ip.IP) {
				s.passIPs[a.Attachment.Name] = append(s.passIPs[a.Attachment.Name], ip.IP)
			}
			err = a.Objects.PassLpmTrie.Update(xdpprog.NewIPLpmKey(ip.IP), uint8(0), 0)
		case model.XDPActionRedirect:
			if !slices.Contains(s.redirectIPs[a.Attachment.Name], ip.IP) {
				s.redirectIPs[a.Attachment.Name] = append(s.redirectIPs[a.Attachment.Name], ip.IP)
			}
			err = a.Objects.RedirectLpmTrie.Update(xdpprog.NewIPLpmKey(ip.IP), uint8(0), 0)
		}
		if err != nil {
			return err
		}
		logrus.WithFields(logrus.Fields{"attachment": ip.AttachmentName, "action": ip.Action}).Info("Added xdp ip")
	}
	return nil
}

func (s *AttachmentService) DeleteIP(ip *model.IP) error {
	if ip.Action != model.XDPActionPass && ip.Action != model.XDPActionRedirect {
		return fmt.Errorf("invalid xdp action: %s", ip.Action)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var attachments []*Attachment
	if ip.AttachmentName == "" {
		attachments = s.attachments
	} else {
		idx := slices.IndexFunc(s.attachments, func(a *Attachment) bool { return a.Name == ip.AttachmentName })
		if idx == -1 {
			return fmt.Errorf("no such attachment: %s", ip.AttachmentName)
		}
		attachments = []*Attachment{s.attachments[idx]}
	}

	for _, a := range attachments {
		var err error
		switch ip.Action {
		case model.XDPActionPass:
			err = s.deleteIP(ip, s.passIPs, a.PassLpmTrie)
		case model.XDPActionRedirect:
			err = s.deleteIP(ip, s.passIPs, a.PassLpmTrie)
		}
		if err != nil {
			return err
		}
		logrus.WithFields(logrus.Fields{"attachment": ip.AttachmentName, "action": ip.Action}).Info("Deleted xdp ip")
	}
	return nil
}

func (s *AttachmentService) deleteIP(ip *model.IP, ips map[string][]netaddr.IPv4Prefix, trie *ebpf.Map) error {
	err := trie.Delete(xdpprog.NewIPLpmKey(ip.IP))
	if err != nil {
		return err
	}
	idx := slices.Index(ips[ip.AttachmentName], ip.IP)
	if idx != -1 {
		ips[ip.AttachmentName] = slices.Delete(ips[ip.AttachmentName], idx, idx+1)
	}
	return nil
}

func (s *AttachmentService) QueryIP(attachmentName string, action model.XDPAction, page, limit int) ([]*model.IP, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch action {
	case model.XDPActionPass:
		return s.queryIP(s.passIPs, attachmentName, action, page, limit)
	case model.XDPActionRedirect:
		return s.queryIP(s.redirectIPs, attachmentName, action, page, limit)
	default:
		pass, pt, err := s.queryIP(s.passIPs, attachmentName, model.XDPActionPass, page, limit)
		if err != nil {
			return nil, 0, err
		}
		redirect, rt, err := s.queryIP(s.redirectIPs, attachmentName, model.XDPActionRedirect, page, limit)
		if err != nil {
			return nil, 0, err
		}
		return append(pass, redirect...), pt + rt, nil
	}
}

func (s *AttachmentService) queryIP(ips map[string][]netaddr.IPv4Prefix, attachmentName string, action model.XDPAction, page, limit int) ([]*model.IP, int, error) {
	var names []string
	if attachmentName == "" {
		for name := range ips {
			names = append(names, name)
		}
	} else {
		names = []string{attachmentName}
	}

	var (
		results []*model.IP
		total   int
	)
	for _, name := range names {
		aips, ok := ips[name]
		if !ok {
			return nil, 0, fmt.Errorf("no such ip by attachment: %s", attachmentName)
		}
		data, t := utils.LimitPageSlice(aips, page, limit)
		total += t
		for _, ip := range data {
			results = append(results, &model.IP{
				AttachmentName: name,
				Action:         action,
				IP:             ip,
			})
		}
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
	doneCh  chan struct{}
}

func NewAttachment(a *model.Attachment, h PacketHandler) (*Attachment, error) {
	l := logrus.WithField("name", a.Name)

	ifaceLink, err := netlink.LinkByName(a.Name)
	if err != nil {
		return nil, errors.Wrap(err, "netlink.LinkByName")
	}
	l.WithFields(logrus.Fields{
		"name": ifaceLink.Attrs().Name, "index": ifaceLink.Attrs().Index,
		"num_rx": ifaceLink.Attrs().NumRxQueues, "num_tx": ifaceLink.Attrs().NumTxQueues,
	}).Info("Found link")

	objs, err := xdpprog.LoadObjects(nil)
	if err != nil {
		return nil, err
	}
	closers := utils.NamedClosers{{Name: "xdpprog.Objects", Close: objs.Close}}

	// Attach xdp program
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRedirectXskProg,
		Interface: ifaceLink.Attrs().Index,
		Flags:     link.XDPGenericMode, // TODO: Add config API
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
		l.WithFields(logrus.Fields{"id": info.ID, "type": info.Type, "prog": info.Program}).Info("Get xdp link info")
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
	l.WithField("queues", queues).Info("Get rx queues")

	var xsks []*xdp.XDPSocket
	for _, queueID := range queues {
		s, err := xdp.NewXDPSocket(uint32(ifaceLink.Attrs().Index), uint32(queueID), xdp.WithFrameSize(xdp.UmemFrameSize2048))
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
		doneCh:     make(chan struct{}),
	}, nil
}

func (a *Attachment) Close() error {
	a.cancel()
	<-a.doneCh

	a.closers.Close(&utils.CloseOpt{
		ReverseOrder: true,
		Output:       logrus.WithField("iface", a.Name).Info,
		ErrorOutput:  logrus.WithField("iface", a.Name).Error,
	})
	return nil
}

type xskGroup struct {
	xsks []*xdp.XDPSocket
	core int
	fds  []unix.PollFd
}

func (a *Attachment) Run() error {
	done := false
	go func() {
		<-a.ctx.Done()
		done = true
	}()
	defer close(a.doneCh)

	cores := a.Cores[:min(len(a.xsks), len(a.Cores))]
	if len(cores) == 0 {
		cores = []int{-1}
	}

	var xskGroups []*xskGroup
	for _, core := range cores {
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

			l := logrus.WithField("tid", unix.Gettid())
			if g.core != -1 {
				setAffinityCPU(g.core)
				l = l.WithField("affinity_core", g.core)
			}
			l.Info("Start xsk group")

			// TODO: use option vec size
			numRxTxData := 64
			rxDataVec := make([][]byte, numRxTxData)
			txDataVec := make([][]byte, numRxTxData)
			tmpTxDataVec := make([][]byte, numRxTxData)
			pkts := make([]*fastpkt.Packet, numRxTxData)
			for i := 0; i < numRxTxData; i++ {
				rxDataVec[i] = make([]byte, xdp.UmemDefaultFrameSize)
				txDataVec[i] = make([]byte, xdp.UmemDefaultFrameSize)
				pkts[i] = &fastpkt.Packet{RxData: rxDataVec[i], TxData: txDataVec[i]}
			}

			for !done {
				err := a.waitPoll(g.fds)
				if err != nil {
					continue
				}
				for _, xsk := range g.xsks {
					for i := 0; i < numRxTxData; i++ {
						pkts[i].Clear()
						pkts[i].RxData = rxDataVec[i]
						pkts[i].TxData = txDataVec[i][:0]
					}
					a.handleXSK(xsk, rxDataVec, tmpTxDataVec, pkts)
				}
			}
		}(xg)
	}
	wg.Wait()

	return nil
}

func (a *Attachment) handleXSK(xsk *xdp.XDPSocket, rxDataVec, tmpTxDataVec [][]byte, pkts []*fastpkt.Packet) {
	n := xsk.Readv(rxDataVec)
	if n == 0 {
		return
	}

	txIdx := 0
	for i := range n {
		err := pkts[i].DecodeFromData(rxDataVec[i])
		if err != nil {
			continue
		}

		a.handler.OnPacket(pkts[i])

		if len(pkts[i].TxData) > 0 {
			tmpTxDataVec[txIdx] = pkts[i].TxData
			txIdx++
		}
	}
	if txIdx > 0 {
		for xsk.Writev(tmpTxDataVec[:txIdx]) == 0 {
		}
	}
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

func setAffinityCPU(cpu int) error {
	var s unix.CPUSet
	s.Zero()
	s.Set(cpu)
	return unix.SchedSetaffinity(0, &s)
}
