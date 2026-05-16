package events

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"
)

// Subscriber receives events from the stream.
type Subscriber struct {
	Events chan Event
	Done   chan struct{}
}

// Stream manages ringbuf readers and SSE subscribers.
type Stream struct {
	mu             sync.RWMutex
	bootTimeOffset int64
	subscribers    map[*Subscriber]struct{}
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

// NewStream creates a new event stream.
func NewStream(ctx context.Context) *Stream {
	ctx, cancel := context.WithCancel(ctx)
	return &Stream{
		bootTimeOffset: BootTimeOffset(),
		subscribers:    make(map[*Subscriber]struct{}),
		ctx:            ctx,
		cancel:         cancel,
	}
}

// Subscribe creates a new subscriber for SSE events.
func (s *Stream) Subscribe() *Subscriber {
	sub := &Subscriber{
		Events: make(chan Event, 64),
		Done:   make(chan struct{}),
	}
	s.mu.Lock()
	s.subscribers[sub] = struct{}{}
	s.mu.Unlock()
	return sub
}

// Unsubscribe removes a subscriber.
func (s *Stream) Unsubscribe(sub *Subscriber) {
	s.mu.Lock()
	delete(s.subscribers, sub)
	s.mu.Unlock()
	close(sub.Done)
}

// StartReader starts a ringbuf reader for an attachment.
// It reads events from the ringbuf and broadcasts them to subscribers.
func (s *Stream) StartReader(ringbufMap *ebpf.Map, ifIndex uint32) error {
	reader, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return fmt.Errorf("create ringbuf reader: %w", err)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer reader.Close()

		logrus.WithField("ifindex", ifIndex).Info("Event ringbuf reader started")
		defer logrus.WithField("ifindex", ifIndex).Info("Event ringbuf reader stopped")

		for {
			record, err := reader.Read()
			if err != nil {
				if s.ctx.Err() != nil {
					return
				}
				logrus.WithError(err).Warn("Ringbuf read error")
				continue
			}

			if len(record.RawSample) < ruleEventSize {
				continue
			}

			var raw [ruleEventSize]byte
			copy(raw[:], record.RawSample[:ruleEventSize])

			event, err := DecodeEvent(raw, ifIndex, s.bootTimeOffset)
			if err != nil {
				logrus.WithError(err).Warn("Event decode error")
				continue
			}

			s.broadcast(event)
		}
	}()

	return nil
}

// broadcast sends an event to all subscribers, dropping for slow clients.
func (s *Stream) broadcast(event Event) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for sub := range s.subscribers {
		select {
		case sub.Events <- event:
		default:
			// Slow subscriber, drop event.
		}
	}
}

// Stop stops all ringbuf readers and waits for them to finish.
func (s *Stream) Stop() {
	s.cancel()
	s.wg.Wait()
}

// SSEWriter is an io.Writer with Flush support for SSE.
type SSEWriter interface {
	Write(p []byte) (n int, err error)
	Flush()
}

// WriteSSE writes events to an SSE response.
func WriteSSE(ctx context.Context, sub *Subscriber, w SSEWriter) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-sub.Done:
			return
		case event, ok := <-sub.Events:
			if !ok {
				return
			}
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: rule_event\ndata: %s\n\n", data)
			w.Flush()
		}
	}
}
