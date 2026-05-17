package dispatch

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"
)

// Runtime manages the dispatch queue and worker.
type Runtime struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	enabled bool
	sender  Sender
	queue   chan []byte
	stats   *Stats
	done    chan struct{}
}

// NewRuntime creates a new dispatch runtime in disabled state.
func NewRuntime(ctx context.Context) *Runtime {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	close(done) // already stopped initially
	return &Runtime{
		ctx:    ctx,
		cancel: cancel,
		stats:  &Stats{},
		done:   done,
	}
}

// Start enables dispatch with the given sender and options.
// If already running, it stops the previous worker first.
func (rt *Runtime) Start(sender Sender, opts Options) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.enabled {
		rt.stopLocked()
	}

	rt.sender = sender
	rt.queue = make(chan []byte, opts.QueueSize)
	rt.enabled = true

	go rt.run(rt.ctx)

	logrus.WithField("queue_size", opts.QueueSize).Info("Dispatch worker started")
	return nil
}

// Stop disables dispatch, stops the worker, and closes the sender.
func (rt *Runtime) Stop() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.stopLocked()
}

func (rt *Runtime) stopLocked() {
	if !rt.enabled {
		return
	}

	rt.cancel()
	<-rt.done

	// Drain remaining packets.
	for len(rt.queue) > 0 {
		<-rt.queue
		rt.stats.DroppedPackets.Add(1)
	}

	if rt.sender != nil {
		rt.sender.Close()
		rt.sender = nil
	}

	rt.enabled = false
	rt.ctx, rt.cancel = context.WithCancel(context.Background())
	rt.done = make(chan struct{})

	logrus.Info("Dispatch worker stopped")
}

// TryEnqueue attempts to enqueue a packet for dispatch.
// Returns true if enqueued, false if dropped (disabled, queue full, etc.).
// The caller should pass a copy of the packet data if it will be reused.
func (rt *Runtime) TryEnqueue(pkt []byte) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if !rt.enabled || rt.sender == nil {
		rt.stats.DroppedPackets.Add(1)
		return false
	}

	rt.stats.EnqueuePackets.Add(1)

	select {
	case rt.queue <- pkt:
		return true
	default:
		rt.stats.QueueFullPackets.Add(1)
		rt.stats.DroppedPackets.Add(1)
		return false
	}
}

// IsEnabled returns whether dispatch is currently enabled.
func (rt *Runtime) IsEnabled() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.enabled
}

// Stats returns the shared stats accumulator.
func (rt *Runtime) Stats() *Stats {
	return rt.stats
}

// run is the dispatch worker loop.
func (rt *Runtime) run(ctx context.Context) {
	defer close(rt.done)

	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-rt.queue:
			if !ok {
				return
			}
			rt.send(pkt)
		}
	}
}

func (rt *Runtime) send(pkt []byte) {
	if err := rt.sender.Send(pkt); err != nil {
		rt.stats.ErrorPackets.Add(1)
		logrus.WithError(err).Debug("Dispatch send failed")
		return
	}
	rt.stats.Packets.Add(1)
}
