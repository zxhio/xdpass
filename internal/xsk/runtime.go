package xsk

import (
	"context"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
)

// StartRequest holds parameters for starting XSK on an attachment.
type StartRequest struct {
	IfIndex uint32
	Queues  []uint32
	Options Options
}

// StartResult holds the result of starting XSK on an attachment.
type StartResult struct {
	PktCh  chan RXEnvelope
	Socket *Socket // first socket, for TX
}

// Runtime manages AF_XDP sockets per attachment.
type Runtime struct {
	mu       sync.Mutex
	ctx      context.Context
	sockets  map[uint32]map[uint32]*Socket // ifindex → queueID → socket
	cancelFn map[uint32]context.CancelFunc  // ifindex → cancel
	channels map[uint32]chan RXEnvelope     // ifindex → packet channel
}

// NewRuntime creates a new XSK runtime.
func NewRuntime(ctx context.Context) *Runtime {
	return &Runtime{
		ctx:      ctx,
		sockets:  make(map[uint32]map[uint32]*Socket),
		cancelFn: make(map[uint32]context.CancelFunc),
		channels: make(map[uint32]chan RXEnvelope),
	}
}

// Start creates XSK sockets for the given attachment's queues, registers them
// in xsks_map, and starts RX goroutines. Returns the combined packet channel
// and the first socket (for TX).
func (rt *Runtime) Start(xsksMap *ebpf.Map, req StartRequest) (*StartResult, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if _, exists := rt.sockets[req.IfIndex]; exists {
		return nil, fmt.Errorf("xsk: already started for ifindex %d", req.IfIndex)
	}

	if len(req.Queues) == 0 {
		return nil, fmt.Errorf("xsk: no queues specified for ifindex %d", req.IfIndex)
	}

	pktCh := make(chan RXEnvelope, 64)
	sockets := make(map[uint32]*Socket, len(req.Queues))
	ctx, cancel := context.WithCancel(rt.ctx)

	var firstSocket *Socket
	for _, queueID := range req.Queues {
		sock, err := NewSocket(req.IfIndex, queueID, req.Options)
		if err != nil {
			// Rollback: close already-created sockets.
			cancel()
			for _, s := range sockets {
				s.Close()
			}
			return nil, fmt.Errorf("xsk: create socket queue %d: %w", queueID, err)
		}

		// Register in xsks_map.
		if err := xsksMap.Put(queueID, sock.FD()); err != nil {
			sock.Close()
			cancel()
			for _, s := range sockets {
				s.Close()
			}
			return nil, fmt.Errorf("xsk: register queue %d in xsks_map: %w", queueID, err)
		}

		sockets[queueID] = sock
		if firstSocket == nil {
			firstSocket = sock
		}

		log := logrus.WithFields(logrus.Fields{
			"component": "xsk_rx",
			"ifindex":   req.IfIndex,
			"queue":     queueID,
		})
		go sock.RunRX(ctx, req.IfIndex, pktCh, log)
	}

	rt.sockets[req.IfIndex] = sockets
	rt.cancelFn[req.IfIndex] = cancel
	rt.channels[req.IfIndex] = pktCh

	logrus.WithFields(logrus.Fields{
		"ifindex": req.IfIndex,
		"queues":  len(req.Queues),
	}).Info("XSK started")

	return &StartResult{PktCh: pktCh, Socket: firstSocket}, nil
}

// Stop stops all XSK sockets for an attachment and removes them from xsks_map.
func (rt *Runtime) Stop(xsksMap *ebpf.Map, ifIndex uint32) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	cancel, ok := rt.cancelFn[ifIndex]
	if !ok {
		return
	}
	cancel()

	sockets := rt.sockets[ifIndex]
	for queueID, sock := range sockets {
		if xsksMap != nil {
			_ = xsksMap.Delete(queueID)
		}
		sock.Close()
	}

	delete(rt.sockets, ifIndex)
	delete(rt.cancelFn, ifIndex)
	delete(rt.channels, ifIndex)

	logrus.WithField("ifindex", ifIndex).Info("XSK stopped")
}

// StopAll stops all XSK sockets.
func (rt *Runtime) StopAll() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for ifIndex, cancel := range rt.cancelFn {
		cancel()
		for _, sock := range rt.sockets[ifIndex] {
			sock.Close()
		}
	}

	rt.sockets = make(map[uint32]map[uint32]*Socket)
	rt.cancelFn = make(map[uint32]context.CancelFunc)
	rt.channels = make(map[uint32]chan RXEnvelope)
}

// Socket returns the first socket for an attachment (for TX), or nil.
func (rt *Runtime) Socket(ifIndex uint32) *Socket {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	sockets := rt.sockets[ifIndex]
	for _, sock := range sockets {
		return sock
	}
	return nil
}

// Channel returns the packet channel for an attachment, or nil.
func (rt *Runtime) Channel(ifIndex uint32) chan RXEnvelope {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	return rt.channels[ifIndex]
}
