package response

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"
)

// Runtime manages response workers for all attachments.
type Runtime struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	workers map[uint32]*workerState // keyed by ifindex
	rules   RuleLookup
	stats   *Stats
}

type workerState struct {
	worker *Worker
	cancel context.CancelFunc
}

// NewRuntime creates a new response runtime.
func NewRuntime(ctx context.Context, rules RuleLookup) *Runtime {
	ctx, cancel := context.WithCancel(ctx)
	return &Runtime{
		ctx:     ctx,
		cancel:  cancel,
		workers: make(map[uint32]*workerState),
		rules:   rules,
		stats:   &Stats{},
	}
}

// Stats returns the shared stats accumulator.
func (rt *Runtime) Stats() *Stats {
	return rt.stats
}

// StartWorker starts a response worker for an attachment.
func (rt *Runtime) StartWorker(ifIndex uint32, egressCfg EgressConfig, pktCh <-chan Envelope, xskFD uint32, txWriter TXWriter) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if _, exists := rt.workers[ifIndex]; exists {
		logrus.WithField("ifindex", ifIndex).Warn("Response worker already running")
		return
	}

	w := NewWorker(ifIndex, rt.rules, rt.stats, egressCfg, xskFD, txWriter)
	wCtx, wCancel := context.WithCancel(rt.ctx)

	rt.workers[ifIndex] = &workerState{
		worker: w,
		cancel: wCancel,
	}

	go w.Run(wCtx, pktCh)
	logrus.WithField("ifindex", ifIndex).Info("Response worker started")
}

// StopWorker stops the response worker for an attachment.
func (rt *Runtime) StopWorker(ifIndex uint32) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	ws, ok := rt.workers[ifIndex]
	if !ok {
		return
	}

	ws.cancel()
	delete(rt.workers, ifIndex)
	logrus.WithField("ifindex", ifIndex).Info("Response worker stopped")
}

// UpdateEgress updates the egress config for all running workers.
func (rt *Runtime) UpdateEgress(cfg EgressConfig) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for _, ws := range rt.workers {
		ws.worker.UpdateEgress(cfg)
	}
	logrus.WithFields(logrus.Fields{
		"workers":        len(rt.workers),
		"configured":     cfg.Configured,
		"egress_ifindex": cfg.EgressIfIndex,
		"vlan_mode":      cfg.VLANMode,
	}).Info("Updated response egress")
}

// Stop stops all response workers.
func (rt *Runtime) Stop() {
	rt.cancel()
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for ifIndex, ws := range rt.workers {
		ws.cancel()
		delete(rt.workers, ifIndex)
	}
}

// UpdateRules replaces the rule lookup data for all workers.
func (rt *Runtime) UpdateRules(rules []RuleEntry) {
	if rl, ok := rt.rules.(*RulesetRuleLookup); ok {
		rl.Rules = rules
		logrus.WithField("rules", len(rules)).Info("Updated response rules")
	}
}

// RulesetRuleLookup adapts an in-memory ruleset to the RuleLookup interface.
type RulesetRuleLookup struct {
	Rules []RuleEntry
}

// RuleEntry holds a rule's action and params for lookup.
type RuleEntry struct {
	RuleID uint32
	Action string
	Params map[string]any
}

// LookupByRuleID finds a rule by ID.
func (rl *RulesetRuleLookup) LookupByRuleID(ruleID uint32) (string, map[string]any, bool) {
	for _, r := range rl.Rules {
		if r.RuleID == ruleID {
			return r.Action, r.Params, true
		}
	}
	return "", nil, false
}
