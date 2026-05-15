package xsk

import (
	"context"
	"encoding/binary"

	"github.com/sirupsen/logrus"
)

// RXEnvelope holds a packet received from XSK with its metadata.
type RXEnvelope struct {
	Packet  []byte
	RuleID  uint32
	Action  uint16
	IfIndex uint32
}

// RunRX starts the RX poll loop, reading packets from the XSK socket and
// sending decoded envelopes to the provided channel. It blocks until ctx is
// cancelled or the socket is closed.
func (s *Socket) RunRX(ctx context.Context, ifIndex uint32, pktCh chan<- RXEnvelope, log *logrus.Entry) {
	log.Info("XSK RX loop started")
	defer log.Info("XSK RX loop stopped")

	for {
		if ctx.Err() != nil {
			return
		}

		frame, err := s.ReadFrame(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.WithError(err).Warn("XSK RX read error")
			continue
		}
		if frame == nil {
			continue
		}

		// The frame includes 8-byte xsk_meta prepended by BPF.
		if len(frame) < 8 {
			log.WithField("len", len(frame)).Warn("XSK frame too short for metadata")
			continue
		}

		meta := RXEnvelope{
			RuleID:  binary.LittleEndian.Uint32(frame[0:4]),
			Action:  binary.LittleEndian.Uint16(frame[4:6]),
			IfIndex: ifIndex,
			Packet:  frame[8:],
		}

		select {
		case <-ctx.Done():
			return
		case pktCh <- meta:
		}
	}
}
