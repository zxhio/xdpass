package dispatch

import "fmt"

const (
	DefaultQueueSize = 4096
	MinQueueSize     = 1
	MaxQueueSize     = 1 << 16 // 65536
)

// Options holds dispatch runtime configuration.
type Options struct {
	QueueSize int
}

// DefaultOptions returns default dispatch options.
func DefaultOptions() Options {
	return Options{QueueSize: DefaultQueueSize}
}

// Validate checks options and applies defaults.
func (o *Options) Validate() error {
	if o.QueueSize == 0 {
		o.QueueSize = DefaultQueueSize
	}
	if o.QueueSize < MinQueueSize || o.QueueSize > MaxQueueSize {
		return fmt.Errorf("queue_size must be between %d and %d", MinQueueSize, MaxQueueSize)
	}
	return nil
}
