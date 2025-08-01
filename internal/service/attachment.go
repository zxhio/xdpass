package service

import (
	"context"
	"fmt"
	"math/bits"
	"os"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
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
		l.WithError(err).Error("Fail to add attachment")
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

	mu        *sync.RWMutex
	cpuQueues []cpuQueue
	xsks      []*xdp.XDPSocket
	closers   utils.NamedClosers
	ctx       context.Context
	cancel    func()
	log       *logrus.Entry
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

	cpuQueues, err := getCpuQueuesWithCombined(ifaceLink, a.Cores, a.Queues)
	if err != nil {
		return nil, err
	}
	queueIDs := []int{}
	for _, cq := range cpuQueues {
		queueIDs = append(queueIDs, cq.queueID)
	}
	queueIRQs, err := getQueueIRQs(a.Name, queueIDs)
	if err != nil {
		return nil, err
	}
	err = setQueueIRQsToCore(a.Name, queueIRQs, cpuQueues)
	if err != nil {
		return nil, err
	}

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

	var xsks []*xdp.XDPSocket
	for _, q := range cpuQueues {
		s, err := xdp.NewXDPSocket(uint32(ifaceLink.Attrs().Index), uint32(q.queueID), append(opts, xdp.WithFrameSize(xdp.UmemFrameSize2048))...)
		if err != nil {
			return nil, err
		}

		closers = append(closers, utils.NamedCloser{Name: fmt.Sprintf("xdp.XDPSocket(fd:%d queue:%d)", s.SocketFD(), q.queueID), Close: s.Close})
		xsks = append(xsks, s)
		l.WithFields(logrus.Fields{"fd": s.SocketFD(), "queue_id": q.queueID}).Info("New xdp socket")

		// Update xsk map
		// Note: xsk map not support lookup element,
		//       See kernel tree net/xdp/xdpmap.c *xsk_map_lookup_elem_sys_only()* implement
		err = objs.XskMap.Update(uint32(q.queueID), uint32(s.SocketFD()), 0)
		if err != nil {
			closers.Close(nil)
			return nil, errors.Wrap(err, "XskMap.Update")
		}
		l.WithFields(logrus.Fields{"k": q.queueID, "v": s.SocketFD()}).Info("Update xsk map")
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Attachment{
		Attachment: a,
		Objects:    objs,
		handler:    h,
		cpuQueues:  cpuQueues,
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

type coreXsks struct {
	core int
	xsks []*xdp.XDPSocket
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

	var groups []*coreXsks
	for _, cq := range a.cpuQueues {
		idx := slices.IndexFunc(groups, func(g *coreXsks) bool { return g.core == cq.coreID })
		if idx == -1 {
			groups = append(groups, &coreXsks{core: cq.coreID})
		}
	}
	for k, xsk := range a.xsks {
		g := groups[k%len(groups)]
		g.xsks = append(g.xsks, xsk)
		g.fds = append(g.fds, unix.PollFd{Fd: int32(xsk.SocketFD()), Events: unix.POLLIN})
	}

	wg := sync.WaitGroup{}
	wg.Add(len(groups))

	for _, xg := range groups {
		go func(g *coreXsks) {
			defer wg.Done()

			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			l := a.log.WithField("tid", unix.Gettid())
			if g.core != -1 {
				l = l.WithField("core", g.core)
				err := utils.SetAffinityCPU(g.core)
				if err != nil {
					l.WithError(err).Warn("Fail to set affinity cpu")
				}
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

func (a *Attachment) GetAllQueueStats() []model.AttachmentStats {
	stats := make([]model.AttachmentStats, 0, len(a.xsks))
	for _, xsk := range a.xsks {
		stats = append(stats, model.AttachmentStats{
			Name:       a.Name,
			QueueID:    xsk.QueueID(),
			Statistics: xsk.Stats(),
		})
	}
	return stats
}

type cpuQueue struct {
	queueID int
	coreID  int
}

var errOpNotSupp = errors.New("Operation not supported")

func getMaxQueueNumByEthtool(linkName string) (int, error) {
	output, err := utils.RunCommand("ethtool", "-l", linkName)
	if err != nil {
		return 0, errors.New(string(output))
	}
	return getMaxQueueNumByContent(string(output))
}

func getMaxQueueNumByContent(content string) (int, error) {
	combinedLines := []string{}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Combined:") {
			combinedLines = append(combinedLines, line)
		}
	}

	var combined int
	for _, line := range combinedLines {
		s := strings.Trim(line, "Combined: \t")
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("invalid Combined queue value %s: %v", s, err)
		}
		combined = max(combined, n)
	}
	return combined, nil
}

func getCpuQueuesWithCombined(link netlink.Link, cores, queues []int) ([]cpuQueue, error) {
	if len(cores) == 0 {
		cores = []int{-1}
	} else if bits.OnesCount32(uint32(len(cores))) != 1 {
		return nil, fmt.Errorf("invalid cpu cores count(%d) of %s, must be a power of 2", len(cores), utils.SliceString(cores))
	}

	var combined int
	if len(queues) == 0 {
		combined = min(link.Attrs().NumRxQueues, len(cores))
	} else {
		combined = link.Attrs().NumRxQueues
	}

	n, err := getMaxQueueNumByEthtool(link.Attrs().Name)
	if err != nil {
		if strings.Contains(err.Error(), errOpNotSupp.Error()) {
			logrus.WithError(err).WithField("name", link.Attrs().Name).Warn("Combined operation not supported, set combined num to 1")
			combined = 1
		} else {
			return nil, err
		}
	} else {
		combined = min(n, combined)

		output, err := utils.RunCommand("ethtool", "-L", link.Attrs().Name, "combined", strconv.Itoa(combined))
		if err != nil {
			err = errors.New(string(output))
			if strings.Contains(err.Error(), errOpNotSupp.Error()) {
				logrus.WithError(err).WithField("name", link.Attrs().Name).Warn("Combined operation not supported")
			} else {
				return nil, err
			}
		} else {
			logrus.WithFields(logrus.Fields{"name": link.Attrs().Name, "n": combined}).Info("Combined link queues")
		}
	}

	if len(queues) == 0 {
		queues, err = netutil.GetRxQueues(link.Attrs().Name)
		if err != nil {
			return nil, err
		}
	} else if slices.ContainsFunc(queues, func(queue int) bool { return queue >= combined }) {
		return nil, fmt.Errorf("invalid queues(%s), exceeds maximum %d", utils.SliceString(queues), combined)
	}

	var cpuQueues []cpuQueue
	for k, queue := range queues {
		cpuQueues = append(cpuQueues, cpuQueue{
			queueID: queue,
			coreID:  cores[k%len(cores)],
		})
	}
	return cpuQueues, nil
}

// Core
//  -1
//    -> Not set affinity
//  *
//    -> Set thread affinity
//    -> Set queue irq affinity
//    -> Combined nic queues to core num (if Supported)

// Queue irq, nic queues num
//  1
//    -> nic irq
// n, Separate rx/tx:
//    -> Set rx/tx queue irq affinity
// n, Combined rx&tx:
//    -> Set rx&tx queue irq affinity

type queueIRQ struct {
	queueID   int
	irqID     int
	queueType string // rx/tx/TxRx
}

func getQueueIRQs(linkName string, queues []int) ([]queueIRQ, error) {
	content, err := os.ReadFile("/proc/interrupts")
	if err != nil {
		return nil, err
	}
	return getQueueIRQsFromData(string(content), linkName, queues)
}

func getQueueIRQsFromData(content string, linkName string, queues []int) ([]queueIRQ, error) {
	lines := strings.Split(string(content), "\n")
	lines = slices.DeleteFunc(lines, func(s string) bool { return !strings.Contains(s, linkName) })

	getQueueIRQ := func(lines []string, queueID int, irqType string, match func(string) bool) ([]queueIRQ, error) {
		idx := slices.IndexFunc(lines, func(s string) bool {
			fields := strings.Fields(s)
			if len(fields) < 2 {
				return false
			}
			return match(fields[len(fields)-1])
		})
		if idx == -1 {
			return []queueIRQ{}, nil
		}
		irq, err := strconv.Atoi(strings.Trim(strings.Fields(lines[idx])[0], " :"))
		if err != nil {
			return []queueIRQ{}, err
		}
		return []queueIRQ{{queueID: queueID, irqID: irq, queueType: irqType}}, nil
	}

	// cat /proc/interrupts | grep enp1s0
	//
	// 1 queues (no rx/tx):
	//   127:          0          0     IR-PCI-MSI 524288-edge      enp1s0
	//
	// 2 queues (rx/tx):
	//   128:          7          0    IR-PCI-MSI 524288-edge      enp1s0
	//   129:          0    5214704    IR-PCI-MSI 524289-edge      enp1s0-rx-0
	//   130:   10123973          0    IR-PCI-MSI 524290-edge      enp1s0-rx-1
	//   131:          0   11679892    IR-PCI-MSI 524291-edge      enp1s0-tx-0
	//   132:    5151333          0    IR-PCI-MSI 524292-edge      enp1s0-tx-1
	//
	// 8 queues (TxRx):
	//   35:          0        0       PCI-MSI 2621440-edge     enp1s0
	//   36:   55627941        0       PCI-MSI 2621441-edge     enp1s0-TxRx-0
	//   37:          0        0       PCI-MSI 2621442-edge     enp1s0-TxRx-1
	//   38:          0        0       PCI-MSI 2621443-edge     enp1s0-TxRx-2
	//   39:          0        0       PCI-MSI 2621444-edge     enp1s0-TxRx-3
	//   40:          0        0       PCI-MSI 2621445-edge     enp1s0-TxRx-4
	//   41:          0        0       PCI-MSI 2621446-edge     enp1s0-TxRx-5
	//   42:          0        0       PCI-MSI 2621447-edge     enp1s0-TxRx-6
	//   43:          0        0       PCI-MSI 2621448-edge     enp1s0-TxRx-7

	var (
		res []queueIRQ
		err error
	)

	if len(queues) == 1 {
		res, err = getQueueIRQ(lines, queues[0], "TxRx", func(s string) bool { return linkName == s })
		if err != nil {
			return nil, err
		}
		if len(res) == 0 {
			return nil, fmt.Errorf("no such link %s irq", linkName)
		}
		return res, nil
	}

	for _, queueID := range queues {
		for _, irqType := range []string{"rx", "tx", "TxRx"} {
			irqs, err := getQueueIRQ(lines, queueID, irqType, func(s string) bool {
				return fmt.Sprintf("%s-%s-%d", linkName, irqType, queueID) == s
			})
			if err != nil {
				return nil, err
			}
			res = append(res, irqs...)
		}
	}
	return res, nil
}

func setQueueIRQsToCore(linkName string, irqs []queueIRQ, cqs []cpuQueue) error {
	if !netutil.IsPhyNic(linkName) {
		return nil
	}
	if slices.ContainsFunc(cqs, func(cq cpuQueue) bool { return cq.coreID == -1 }) {
		return nil
	}

	for _, irq := range irqs {
		idx := slices.IndexFunc(cqs, func(cq cpuQueue) bool { return cq.queueID == irq.queueID })
		if idx == -1 {
			return fmt.Errorf("no such core for queue %d irq %d", irq.queueID, irq.irqID)
		}

		coreOff := fmt.Sprintf("%x", 1<<cqs[idx].coreID)
		err := os.WriteFile(path.Join("/proc/irq", strconv.Itoa(irq.irqID), "smp_affinity"), []byte(coreOff), 0644)
		if err != nil {
			return fmt.Errorf("set queue %d irq %d affinity: %v", irq.queueID, irq.irqID, err)
		}
		logrus.WithFields(logrus.Fields{
			"name":        linkName,
			"core_id":     cqs[idx].coreID,
			"core_offset": coreOff,
			"queue":       irq.queueID,
			"queue_type":  irq.queueType,
			"irq":         irq.irqID,
		}).Info("Set link queue affinity")
	}
	return nil
}
