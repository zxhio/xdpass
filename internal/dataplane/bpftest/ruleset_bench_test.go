package bpftest

import (
	"testing"

	"xdpass/internal/dataplane/bpfgen"
	"xdpass/internal/ruleset"
)

type benchmarkSetup struct {
	objs *bpfgen.XdpassObjects
	pkt  []byte
}

func newBenchmarkSetup(b *testing.B, rules []ruleset.Rule, ingressVerdict string, pkt []byte) *benchmarkSetup {
	b.Helper()

	removeMemlock(b)
	objs := loadObjects(b)
	compileAndWrite(b, objs, rules, ingressVerdict)
	return &benchmarkSetup{objs: objs, pkt: pkt}
}

func BenchmarkMatchEmptyRuleset(b *testing.B) {
	skipUnlessBPF(b)
	s := newBenchmarkSetup(b, nil, "pass", tcpPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatchSingleWildcard(b *testing.B) {
	skipUnlessBPF(b)
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{}, Response: ruleset.Response{Action: "none"}},
	}
	s := newBenchmarkSetup(b, rules, "pass", tcpPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatchDstPortHit(b *testing.B) {
	skipUnlessBPF(b)
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstPorts: []uint16{80}}, Response: ruleset.Response{Action: "none"}},
	}
	s := newBenchmarkSetup(b, rules, "pass", tcpPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatchDstPortMiss(b *testing.B) {
	skipUnlessBPF(b)
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstPorts: []uint16{443}}, Response: ruleset.Response{Action: "none"}},
	}
	s := newBenchmarkSetup(b, rules, "pass", tcpPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatchCIDRHit(b *testing.B) {
	skipUnlessBPF(b)
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstCIDRs: []string{"192.168.1.0/24"}}, Response: ruleset.Response{Action: "none"}},
	}
	s := newBenchmarkSetup(b, rules, "pass", tcpPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatchCIDRMiss(b *testing.B) {
	skipUnlessBPF(b)
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstCIDRs: []string{"10.0.0.0/8"}}, Response: ruleset.Response{Action: "none"}},
	}
	s := newBenchmarkSetup(b, rules, "pass", tcpPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatchMixedRules(b *testing.B) {
	skipUnlessBPF(b)
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "udp", DstPorts: []uint16{53}}, Response: ruleset.Response{Action: "none"}},
		{RuleID: 2, Priority: 20, Match: ruleset.Match{Protocol: "tcp", DstCIDRs: []string{"10.0.0.0/8"}}, Response: ruleset.Response{Action: "none"}},
		{RuleID: 3, Priority: 30, Match: ruleset.Match{Protocol: "tcp", DstPorts: []uint16{80}}, Response: ruleset.Response{Action: "none"}},
		{RuleID: 4, Priority: 40, Match: ruleset.Match{Protocol: "icmp"}, Response: ruleset.Response{Action: "none"}},
		{RuleID: 5, Priority: 50, Match: ruleset.Match{Protocol: "arp"}, Response: ruleset.Response{Action: "none"}},
	}
	s := newBenchmarkSetup(b, rules, "pass", tcpPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func generateRules(n int) []ruleset.Rule {
	rules := make([]ruleset.Rule, n)
	for i := range n - 1 {
		rules[i] = ruleset.Rule{
			RuleID:   uint32(i + 1),
			Priority: uint32((i + 1) * 10),
			Match:    ruleset.Match{Protocol: "tcp", DstPorts: []uint16{uint16(1000 + i)}},
			Response: ruleset.Response{Action: "none"},
		}
	}
	rules[n-1] = ruleset.Rule{
		RuleID:   uint32(n),
		Priority: uint32(n * 10),
		Match:    ruleset.Match{Protocol: "tcp", DstPorts: []uint16{80}},
		Response: ruleset.Response{Action: "none"},
	}
	return rules
}

func BenchmarkMatch1Rule(b *testing.B) {
	skipUnlessBPF(b)
	s := newBenchmarkSetup(b, generateRules(1), "pass", tcpPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatch10Rules(b *testing.B) {
	skipUnlessBPF(b)
	s := newBenchmarkSetup(b, generateRules(10), "pass", tcpPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatch100Rules(b *testing.B) {
	skipUnlessBPF(b)
	s := newBenchmarkSetup(b, generateRules(100), "pass", tcpPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatch512RulesLateHit(b *testing.B) {
	skipUnlessBPF(b)
	s := newBenchmarkSetup(b, generateRules(512), "pass", tcpPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatch4096RulesLateHit(b *testing.B) {
	skipUnlessBPF(b)
	s := newBenchmarkSetup(b, generateRules(4096), "pass", tcpPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func benchmarkMatchRulesMiss(b *testing.B, n int) {
	rules := make([]ruleset.Rule, n)
	for i := range n {
		rules[i] = ruleset.Rule{
			RuleID:   uint32(i + 1),
			Priority: uint32((i + 1) * 10),
			Match:    ruleset.Match{Protocol: "tcp", DstPorts: []uint16{uint16(1000 + i)}},
			Response: ruleset.Response{Action: "none"},
		}
	}
	s := newBenchmarkSetup(b, rules, "pass", tcpPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatch512RulesMiss(b *testing.B) {
	skipUnlessBPF(b)
	benchmarkMatchRulesMiss(b, 512)
}

func BenchmarkMatch1024RulesMiss(b *testing.B) {
	skipUnlessBPF(b)
	benchmarkMatchRulesMiss(b, 1024)
}

func BenchmarkMatch2048RulesMiss(b *testing.B) {
	skipUnlessBPF(b)
	benchmarkMatchRulesMiss(b, 2048)
}

func BenchmarkMatch4096RulesMiss(b *testing.B) {
	skipUnlessBPF(b)
	benchmarkMatchRulesMiss(b, 4096)
}
