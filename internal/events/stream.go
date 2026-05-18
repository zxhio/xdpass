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

// readerEntry tracks a ringbuf reader and its goroutine.
type readerEntry struct {
	reader *ringbuf.Reader
	wg     sync.WaitGroup
}

// Stream manages ringbuf readers and SSE subscribers.
type Stream struct {
	mu             sync.RWMutex
	bootTimeOffset int64
	subscribers    map[*Subscriber]struct{}
	readers        map[uint32]*readerEntry
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewStream creates a new event stream.
func NewStream(ctx context.Context) *Stream {
	ctx, cancel := context.WithCancel(ctx)
	return &Stream{
		bootTimeOffset: BootTimeOffset(),
		subscribers:    make(map[*Subscriber]struct{}),
		readers:        make(map[uint32]*readerEntry),
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
// Returns an error if a reader for the same ifindex is already running.
func (s *Stream) StartReader(ringbufMap *ebpf.Map, ifIndex uint32) error {
	s.mu.Lock()
	if _, exists := s.readers[ifIndex]; exists {
		s.mu.Unlock()
		return fmt.Errorf("reader already started for ifindex %d", ifIndex)
	}

	reader, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("create ringbuf reader: %w", err)
	}
	entry := &readerEntry{reader: reader}
	entry.wg.Add(1)
	s.readers[ifIndex] = entry
	s.mu.Unlock()

	go func() {
		defer entry.wg.Done()

		logrus.WithField("ifindex", ifIndex).Info("Event ringbuf reader started")
		defer logrus.WithField("ifindex", ifIndex).Info("Event ringbuf reader stopped")

		for {
			record, err := reader.Read()
			if err != nil {
				// reader.Close() was called or context cancelled.
				return
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

// StopReader stops the ringbuf reader for a specific ifindex.
func (s *Stream) StopReader(ifIndex uint32) {
	s.mu.Lock()
	entry, ok := s.readers[ifIndex]
	if !ok {
		s.mu.Unlock()
		return
	}
	delete(s.readers, ifIndex)
	s.mu.Unlock()

	entry.reader.Close()
	entry.wg.Wait()
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

// Stop closes all ringbuf readers and waits for them to finish.
func (s *Stream) Stop() {
	s.cancel()

	s.mu.Lock()
	entries := make([]*readerEntry, 0, len(s.readers))
	for ifIndex, entry := range s.readers {
		entries = append(entries, entry)
		delete(s.readers, ifIndex)
	}
	s.mu.Unlock()

	for _, entry := range entries {
		entry.reader.Close()
	}
	for _, entry := range entries {
		entry.wg.Wait()
	}
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
