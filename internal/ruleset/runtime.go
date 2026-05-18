package ruleset

import (
	"fmt"
	"sync"

	"xdpass/internal/attachment"
)

// MapAccessorFunc returns MapAccessors for all enabled attachments.
type MapAccessorFunc func() []attachment.MapAccessor

// Runtime manages the current ruleset and coordinates apply/delete.
type Runtime struct {
	mu         sync.RWMutex
	rules      []Rule
	compiled   *CompiledRuleset
	generation uint64
}

// NewRuntime creates a new ruleset runtime.
func NewRuntime() *Runtime {
	return &Runtime{}
}

// GetRuleset returns a copy of the current rules.
func (rt *Runtime) GetRuleset() []Rule {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	rules := make([]Rule, len(rt.rules))
	copy(rules, rt.rules)
	return rules
}

// CurrentCompiled returns the current compiled ruleset and its generation.
// Returns nil, 0 if no ruleset is loaded.
func (rt *Runtime) CurrentCompiled() (*CompiledRuleset, uint64) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.compiled, rt.generation
}

// HasUserspaceActions reports whether the current ruleset contains any userspace response actions.
func (rt *Runtime) HasUserspaceActions() bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for _, r := range rt.rules {
		if IsUserspaceAction(r.Response.Action) {
			return true
		}
	}
	return false
}

// ReplaceRuleset validates, compiles, and applies a new ruleset.
// It uses getMaps to obtain MapAccessors for all enabled attachments.
// On failure at any step, the old ruleset is preserved.
func (rt *Runtime) ReplaceRuleset(rules []Rule, ingressVerdict string, getMaps MapAccessorFunc) error {
	// Phase 1: validate + compile.
	compiled, err := Compile(rules, ingressVerdict)
	if err != nil {
		return err
	}

	// Phase 2: write to all enabled attachments.
	maps := getMaps()
	for _, m := range maps {
		if err := WriteMaps(m, compiled); err != nil {
			// Rollback: restore old ruleset in maps.
			rt.rollbackMaps(getMaps)
			return fmt.Errorf("write maps: %w", err)
		}
	}

	// Phase 3: commit.
	rt.mu.Lock()
	rt.rules = make([]Rule, len(rules))
	copy(rt.rules, rules)
	rt.compiled = compiled
	rt.generation++
	rt.mu.Unlock()

	return nil
}

// DeleteRuleset clears the current ruleset and all related BPF maps.
func (rt *Runtime) DeleteRuleset(getMaps MapAccessorFunc) error {
	maps := getMaps()
	for _, m := range maps {
		if err := ClearMaps(m); err != nil {
			return fmt.Errorf("clear maps: %w", err)
		}
	}

	rt.mu.Lock()
	rt.rules = nil
	rt.compiled = nil
	rt.generation = 0
	rt.mu.Unlock()

	return nil
}

// rollbackMaps attempts to restore the old compiled ruleset to all maps.
func (rt *Runtime) rollbackMaps(getMaps MapAccessorFunc) {
	rt.mu.RLock()
	compiled := rt.compiled
	rt.mu.RUnlock()

	if compiled == nil {
		// No previous ruleset, just clear maps.
		for _, m := range getMaps() {
			ClearMaps(m)
		}
		return
	}

	for _, m := range getMaps() {
		WriteMaps(m, compiled)
	}
}
