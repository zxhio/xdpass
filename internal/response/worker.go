package response

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/sirupsen/logrus"
)

// Worker processes packets from XSK RX ring and dispatches to response builders.
type Worker struct {
	ifIndex   uint32
	rules     RuleLookup
	stats     *Stats
	egressCfg EgressConfig
	xskFD     uint32
	txWriter  TXWriter
	log       *logrus.Entry
}

// EgressConfig holds the current response egress configuration.
type EgressConfig struct {
	Configured      bool
	EgressIfIndex   uint32
	VLANMode        string
}

// NewWorker creates a new response worker for an attachment.
func NewWorker(ifIndex uint32, rules RuleLookup, stats *Stats, egressCfg EgressConfig, xskFD uint32, txWriter TXWriter) *Worker {
	return &Worker{
		ifIndex:   ifIndex,
		rules:     rules,
		stats:     stats,
		egressCfg: egressCfg,
		xskFD:     xskFD,
		txWriter:  txWriter,
		log: logrus.WithFields(logrus.Fields{
			"component": "response_worker",
			"ifindex":   ifIndex,
		}),
	}
}

// UpdateEgress updates the worker's egress configuration.
func (w *Worker) UpdateEgress(cfg EgressConfig) {
	w.egressCfg = cfg
}

// ProcessPacket processes a single packet from XSK with its metadata.
// This is the main entry point for packet processing.
func (w *Worker) ProcessPacket(pkt []byte, meta XSKMeta) {
	w.stats.XSKRXPackets.Add(1)

	action, params, ok := w.rules.LookupByRuleID(meta.RuleID)
	if !ok {
		w.log.WithField("rule_id", meta.RuleID).Warn("Rule not found")
		w.stats.ErrorPackets.Add(1)
		return
	}

	builder := BuilderForAction(meta.Action)
	if builder == nil {
		w.log.WithFields(logrus.Fields{
			"rule_id": meta.RuleID,
			"action":  action,
		}).Warn("Unimplemented action")
		w.stats.ErrorPackets.Add(1)
		return
	}

	respPkt, err := builder(pkt, params)
	if err != nil {
		w.log.WithError(err).WithFields(logrus.Fields{
			"rule_id": meta.RuleID,
			"action":  action,
		}).Warn("Build response failed")
		w.stats.ErrorPackets.Add(1)
		return
	}

	// Determine sender based on egress config.
	samePort := !w.egressCfg.Configured
	sender, err := NewSender(samePort, w.txWriter, w.ifIndex, w.egressCfg.EgressIfIndex)
	if err != nil {
		w.log.WithError(err).Warn("Create sender failed")
		w.stats.ErrorPackets.Add(1)
		return
	}
	defer sender.Close()

	vlanMode := w.egressCfg.VLANMode
	if err := SendWithVLAN(sender, respPkt, vlanMode); err != nil {
		w.log.WithError(err).Warn("Send response failed")
		w.stats.ErrorPackets.Add(1)
		return
	}

	w.stats.Packets.Add(1)
	if samePort {
		w.stats.XSKTXPackets.Add(1)
	} else {
		w.stats.AFPacketTXPackets.Add(1)
	}

	w.log.WithFields(logrus.Fields{
		"rule_id": meta.RuleID,
		"action":  action,
	}).Debug("Response sent")
}

// DecodeXSKMeta extracts xsk_meta from XDP metadata preceding the packet.
// The metadata is 8 bytes: rule_id (u32), action (u16), reserved (u16).
func DecodeXSKMeta(metaBytes []byte) (XSKMeta, error) {
	if len(metaBytes) < 8 {
		return XSKMeta{}, fmt.Errorf("xsk metadata too short: %d bytes", len(metaBytes))
	}
	return XSKMeta{
		RuleID: binary.LittleEndian.Uint32(metaBytes[0:4]),
		Action: binary.LittleEndian.Uint16(metaBytes[4:6]),
	}, nil
}

// Run starts the worker loop, reading packets from the provided channel.
// The channel should yield (packet, metadata) pairs from XSK RX ring.
func (w *Worker) Run(ctx context.Context, pktCh <-chan Envelope) {
	w.log.Info("Response worker started")
	defer w.log.Info("Response worker stopped")

	for {
		select {
		case <-ctx.Done():
			return
		case env, ok := <-pktCh:
			if !ok {
				return
			}
			w.ProcessPacket(env.Packet, env.Meta)
		}
	}
}
