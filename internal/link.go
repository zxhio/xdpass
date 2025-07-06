package internal

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/internal/api"
	"github.com/zxhio/xdpass/internal/rule"
	"github.com/zxhio/xdpass/internal/xdpprog"
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netaddr"
	"github.com/zxhio/xdpass/pkg/netutil"
	"github.com/zxhio/xdpass/pkg/utils"
	"github.com/zxhio/xdpass/pkg/xdp"
	"golang.org/x/sys/unix"
)

type linkHandleOpts struct {
	queueID     int
	attachMode  xdp.XDPAttachMode
	xdpOpts     []xdp.XDPOpt
	pollTimeout int
	cores       []int
}

type LinkHandleOpt func(*linkHandleOpts)

func WithLinkQueueID(queueID int) LinkHandleOpt {
	return func(o *linkHandleOpts) { o.queueID = queueID }
}

func WithLinkXDPFlags(attachMode xdp.XDPAttachMode, opts ...xdp.XDPOpt) LinkHandleOpt {
	return func(o *linkHandleOpts) {
		o.attachMode = attachMode
		o.xdpOpts = opts
	}
}

func WithLinkHandleTimeout(timeoutMs int) LinkHandleOpt {
	return func(o *linkHandleOpts) { o.pollTimeout = timeoutMs }
}

func WithLinkHandleCores(cores []int) LinkHandleOpt {
	return func(o *linkHandleOpts) { o.cores = cores }
}

type LinkHandle struct {
	name string
	*linkHandleOpts
	*xdpprog.Objects
	xsks    []*xdp.XDPSocket
	closers utils.NamedClosers

	mu          *sync.RWMutex
	ruleID      int
	rules       []*rule.Rule
	passIPs     []netaddr.IPv4Prefix
	redirectIPs []netaddr.IPv4Prefix
}

func NewLinkHandle(name string, opts ...LinkHandleOpt) (*LinkHandle, error) {
	var o linkHandleOpts
	for _, opt := range opts {
		opt(&o)
	}

	l := logrus.WithField("name", name)

	ifaceLink, err := netlink.LinkByName(name)
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
		Flags:     link.XDPAttachFlags(o.attachMode),
	})
	if err != nil {
		closers.Close(nil)
		return nil, errors.Wrap(err, "link.AttachXDP")
	}
	closers = append(closers, utils.NamedCloser{Name: "ebpf.Link", Close: xdpLink.Close})
	l.WithField("flags", o.attachMode).Info("Attached xdp prog")

	info, err := xdpLink.Info()
	if err != nil {
		l.WithError(err).Warn("Fail to get xdp link info")
	} else {
		l.WithFields(logrus.Fields{"id": info.ID, "type": info.Type, "prog": info.Program}).Info("Get xdp link info")
	}

	// Generate xdp socket per queue
	var queues []int
	if o.queueID == -1 {
		queues, err = netutil.GetRxQueues(name)
		if err != nil {
			return nil, err
		}
	} else {
		queues = []int{o.queueID}
	}
	l.WithField("queues", queues).Info("Get rx queues")

	var xsks []*xdp.XDPSocket
	for _, queueID := range queues {
		s, err := xdp.NewXDPSocket(uint32(ifaceLink.Attrs().Index), uint32(queueID), append(o.xdpOpts, xdp.WithFrameSize(xdp.UmemFrameSize2048))...)
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

	return &LinkHandle{
		name:           name,
		linkHandleOpts: &o,
		xsks:           xsks,
		Objects:        objs,
		closers:        closers,
		mu:             &sync.RWMutex{},
		rules:          make([]*rule.Rule, 0, 128),
	}, nil
}

func (x *LinkHandle) Close() error {
	x.closers.Close(&utils.CloseOpt{
		ReverseOrder: true,
		Output:       logrus.WithField("iface", x.name).Info,
		ErrorOutput:  logrus.WithField("iface", x.name).Error,
	})
	return nil
}

type xskGroup struct {
	xsks []*xdp.XDPSocket
	core int
	fds  []unix.PollFd
}

func (x *LinkHandle) Run(ctx context.Context) error {
	done := false
	go func() {
		<-ctx.Done()
		done = true
	}()

	cores := x.cores[:min(len(x.xsks), len(x.cores))]
	if len(cores) == 0 {
		cores = []int{-1}
	}

	var xskGroups []*xskGroup
	for _, core := range cores {
		xskGroups = append(xskGroups, &xskGroup{core: core})
	}
	for k, xsk := range x.xsks {
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
				err := x.waitPoll(g.fds)
				if err != nil {
					continue
				}
				for _, xsk := range g.xsks {
					for i := 0; i < numRxTxData; i++ {
						pkts[i].Clear()
						pkts[i].RxData = rxDataVec[i]
						pkts[i].TxData = txDataVec[i][:0]
					}
					x.handleXSK(xsk, rxDataVec, tmpTxDataVec, pkts)
				}
			}
		}(xg)
	}
	wg.Wait()

	return nil
}

func (x *LinkHandle) handleXSK(xsk *xdp.XDPSocket, rxDataVec, tmpTxDataVec [][]byte, pkts []*fastpkt.Packet) {
	n := xsk.Readv(rxDataVec)
	if n == 0 {
		return
	}

	txIdx := 0
	for i := uint32(0); i < n; i++ {
		err := pkts[i].DecodeFromData(rxDataVec[i])
		if err != nil {
			continue
		}

		x.handlePacket(pkts[i])

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

func (x *LinkHandle) waitPoll(fds []unix.PollFd) error {
	if x.pollTimeout == 0 {
		return nil
	}

	_, err := unix.Poll(fds, x.pollTimeout)
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			return nil
		}
		return errors.Wrap(err, "unix.Poll")
	}
	return nil
}

func (x *LinkHandle) handlePacket(pkt *fastpkt.Packet) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{
			"l3_proto": pkt.L3Proto,
			"l4_proto": pkt.L4Proto,
			"l7_proto": pkt.L7Proto,
			"src_ip":   pkt.SrcIP,
			"dst_ip":   pkt.DstIP,
			"src_port": pkt.SrcPort,
			"dst_port": pkt.DstPort,
		}).Debug("Handle packet")
	}

	for _, rule := range x.rules {
		matched := true

		for _, m := range rule.Matchs {
			if !m.Match(pkt) {
				matched = false
				break
			}
		}

		if matched {
			if logrus.GetLevel() >= logrus.DebugLevel {
				logrus.WithFields(logrus.Fields{
					"l3_proto":    pkt.L3Proto,
					"l4_proto":    pkt.L4Proto,
					"l7_proto":    pkt.L7Proto,
					"src_ip":      pkt.SrcIP,
					"dst_ip":      pkt.DstIP,
					"src_port":    pkt.SrcPort,
					"dst_port":    pkt.DstPort,
					"target_type": rule.Target.TargetType(),
				}).Debug("Handle packet")
			}
			if err := rule.Target.Execute(pkt); err != nil {
				logrus.WithError(err).Error("Handle packet error")
			}
			break
		}
	}
}

func (x *LinkHandle) QueryRule(ruleID int) (*rule.Rule, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	idx := slices.IndexFunc(x.rules, ruleIDMatcher(ruleID))
	if idx == -1 {
		return nil, errors.Errorf("no such rule id: %d", ruleID)
	}
	return x.rules[idx], nil
}

func (x *LinkHandle) QueryRules(req *api.QueryRulesReq) (*api.QueryRulesResp, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	validateMatch := func(r *rule.Rule) bool {
		if len(req.MatchTypes) == 0 {
			return true
		}
		return slices.ContainsFunc(r.Matchs, func(m rule.Match) bool {
			return slices.Contains(req.MatchTypes, m.MatchType())
		})
	}

	resp := api.QueryWithPage(x.rules, &req.QueryPage, validateMatch)
	return (*api.QueryRulesResp)(resp), nil
}

func (x *LinkHandle) AddRule(r *rule.Rule) (int, error) {
	x.mu.Lock()
	defer x.mu.Unlock()

	x.ruleID++
	r.ID = x.ruleID
	x.rules = append(x.rules, r)
	return r.ID, nil
}

func (x *LinkHandle) DeleteRule(ruleID int) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	idx := slices.IndexFunc(x.rules, ruleIDMatcher(ruleID))
	if idx == -1 {
		return errors.Errorf("no such rule id: %d", ruleID)
	}
	x.rules = slices.DeleteFunc(x.rules, ruleIDMatcher(ruleID))
	return nil
}

func ruleIDMatcher(ruleID int) func(r *rule.Rule) bool {
	return func(r *rule.Rule) bool { return r.ID == ruleID }
}

func (x *LinkHandle) QueryIPs(req *api.QueryIPsReq) (*api.QueryIPsResp, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	var resp *api.QueryPageResp[netaddr.IPv4Prefix]
	switch req.Action {
	case api.XDPActionPass:
		resp = api.QueryWithPage(x.passIPs, &req.QueryPage, nil)
	case api.XDPActionRedirect:
		resp = api.QueryWithPage(x.redirectIPs, &req.QueryPage, nil)
	default:
		return nil, fmt.Errorf("invalid xdp action: %s", req.Action)
	}
	return (*api.QueryIPsResp)(resp), nil
}

func (x *LinkHandle) AddIP(ip netaddr.IPv4Prefix, action api.XDPAction) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	switch action {
	case api.XDPActionPass:
		if !slices.Contains(x.passIPs, ip) {
			x.passIPs = append(x.passIPs, ip)
		}
		return x.Objects.PassLpmTrie.Update(xdpprog.NewIPLpmKey(ip), uint8(0), 0)
	case api.XDPActionRedirect:
		if !slices.Contains(x.redirectIPs, ip) {
			x.passIPs = append(x.passIPs, ip)
		}
		return x.Objects.RedirectLpmTrie.Update(xdpprog.NewIPLpmKey(ip), uint8(0), 0)
	default:
		return fmt.Errorf("invalid xdp action: %s", action)
	}
}

func (x *LinkHandle) DeleteIP(ip netaddr.IPv4Prefix, action api.XDPAction) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	switch action {
	case api.XDPActionPass:
		return x.deleteIP(ip, &x.passIPs, x.Objects.PassLpmTrie)
	case api.XDPActionRedirect:
		return x.deleteIP(ip, &x.redirectIPs, x.Objects.RedirectLpmTrie)
	default:
		return fmt.Errorf("unsupported xdp action: %s", action)
	}
}

func (x *LinkHandle) deleteIP(ip netaddr.IPv4Prefix, ips *[]netaddr.IPv4Prefix, trie *ebpf.Map) error {
	err := trie.Delete(xdpprog.NewIPLpmKey(ip))
	if err != nil {
		return err
	}
	idx := slices.Index(*ips, ip)
	if idx != -1 {
		*ips = slices.Delete(*ips, idx, idx+1)
	}
	return nil
}

func setAffinityCPU(cpu int) error {
	var s unix.CPUSet
	s.Zero()
	s.Set(cpu)
	return unix.SchedSetaffinity(0, &s)
}
