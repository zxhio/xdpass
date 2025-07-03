package main

import (
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/rule"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

type RuleFlags struct {
	// L2
	SrcMAC netaddr.HwAddr
	DstMAC netaddr.HwAddr

	RuleARPFlags

	// L3
	SrcIPv4Prefix netaddr.IPv4Prefix
	DstIPv4Prefix netaddr.IPv4Prefix
	SrcIPv4Range  netaddr.IPv4Range
	DstIPv4Range  netaddr.IPv4Range

	// L4
	RulePortFlags
	TCP  RuleTCPFlags
	ICMP RuleICMPFlags

	// L7
	RuleHTTPFlags

	// Target
	MirrorUDP    string
	MirrorTap    string
	MirrorStdout bool
}

type RuleARPFlags struct {
	SpoofARPReply     bool
	SpoofARPReplyAddr netaddr.HwAddr
}

type RulePortFlags struct {
	SrcPortRange netaddr.PortRange
	DstPortRange netaddr.PortRange
	SrcMultiPort netaddr.MultiPort
	DstMultiPort netaddr.MultiPort
}

type RuleTCPFlags struct {
	SpoofHandshake bool
	ResetHandshake bool
}

type RuleICMPFlags struct {
	SpoofEchoReply bool
}

type RuleHTTPFlags struct {
	Method  string
	URI     string
	Version string
	Host    string
}

var (
	F RuleFlags
	R rule.Rule
)

var ruleGroup = cobra.Group{ID: "rule", Title: "Rule-Protocol-Based Commands:"}

var ruleCmd = &cobra.Command{
	Use:   "rule",
	Short: "Manage rules for matching TCP/IP layer fields and specifying target",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// L3
		if F.SrcIPv4Prefix.Compare(netaddr.IPv4Prefix{}) != 0 {
			R.Matchs = append(R.Matchs, rule.MatchIPv4PrefixSrc(F.SrcIPv4Prefix))
		} else if F.SrcIPv4Range.Compare(netaddr.IPv4Range{}) != 0 {
			R.Matchs = append(R.Matchs, rule.MatchIPv4RangeSrc(F.SrcIPv4Range))
		}

		if F.DstIPv4Prefix.Compare(netaddr.IPv4Prefix{}) != 0 {
			R.Matchs = append(R.Matchs, rule.MatchIPv4PrefixDst(F.DstIPv4Prefix))
		} else if F.DstIPv4Range.Compare(netaddr.IPv4Range{}) != 0 {
			R.Matchs = append(R.Matchs, rule.MatchIPv4RangeDst(F.DstIPv4Range))
		}

		if F.SrcPortRange.Compare(netaddr.PortRange{}) != 0 {
			R.Matchs = append(R.Matchs, rule.MatchPortRangeSrc(F.SrcPortRange))
		} else if F.SrcMultiPort.Compare(netaddr.MultiPort{}) != 0 {
			R.Matchs = append(R.Matchs, rule.MatchMultiPortSrc(F.SrcMultiPort))
		}

		if F.DstPortRange.Compare(netaddr.PortRange{}) != 0 {
			R.Matchs = append(R.Matchs, rule.MatchPortRangeDst(F.DstPortRange))
		} else if F.DstMultiPort.Compare(netaddr.MultiPort{}) != 0 {
			R.Matchs = append(R.Matchs, rule.MatchMultiPortDst(F.DstMultiPort))
		}
	},
}

var arpCmd = &cobra.Command{
	Use:     "arp",
	Short:   "Matches ARP layer fields and specifies the target",
	Aliases: []string{"rule arp"},
	GroupID: ruleGroup.ID,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		R.Matchs = append(R.Matchs, rule.MatchARP{})
		if F.SpoofARPReplyAddr.Compare(netaddr.HwAddr{}) != 0 {
			R.Target = rule.TargetARPReplySpoof{HwAddr: F.SpoofARPReplyAddr}
		}
	},
}

var tcpCmd = &cobra.Command{
	Use:     "tcp",
	Short:   "Matches TCP layer fields and specifies the target",
	Aliases: []string{"rule tcp"},
	GroupID: ruleGroup.ID,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		R.Matchs = append(R.Matchs, rule.MatchTCP{})
		if F.TCP.SpoofHandshake {
			R.Target = rule.TargetTCPSpoofHandshake{}
		} else if F.TCP.ResetHandshake {
			R.Target = rule.TargetTCPResetHandshake{}
		}
	},
}

var udpCmd = &cobra.Command{
	Use:     "udp",
	Short:   "Matches UDP layer fields and specifies the target",
	Aliases: []string{"rule udp"},
	GroupID: ruleGroup.ID,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		R.Matchs = append(R.Matchs, rule.MatchUDP{})
	},
}

var icmpCmd = &cobra.Command{
	Use:     "icmp",
	Short:   "Matches ICMP layer fields and specifies the target",
	Aliases: []string{"rule icmp"},
	GroupID: ruleGroup.ID,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		R.Matchs = append(R.Matchs, rule.MatchICMP{})
		if F.ICMP.SpoofEchoReply {
			R.Target = rule.TargetICMPEchoReplySpoof{}
		}
	},
}

var httpCmd = &cobra.Command{
	Use:     "http",
	Short:   "Matches HTTP layer fields and specifies the target",
	Aliases: []string{"rule http", "rule tcp http"},
	GroupID: ruleGroup.ID,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		R.Matchs = append(R.Matchs, rule.MatchHTTP{})
	},
}

func init() {
	// rule
	ruleCmd.PersistentFlags().Var(&F.SrcMAC, "smac", "Source mac address")
	ruleCmd.PersistentFlags().Var(&F.DstMAC, "dmac", "Destionation mac address")
	ruleCmd.PersistentFlags().VarP(&F.SrcIPv4Prefix, "source", "s", "Source ip address")
	ruleCmd.PersistentFlags().VarP(&F.DstIPv4Prefix, "destination", "d", "Destionation ip address")
	ruleCmd.PersistentFlags().Var(&F.SrcIPv4Range, "iprange-src", "Source ipv4 range address")
	ruleCmd.PersistentFlags().Var(&F.DstIPv4Range, "iprange-dst", "Destionation ipv4 range address")
	ruleCmd.PersistentFlags().BoolVar(&F.MirrorStdout, "mirror-stdout", false, "Target for mirror traffic to stdout")
	ruleCmd.PersistentFlags().StringVar(&F.MirrorTap, "mirror-tap", "", "Target for mirror traffic to tap device")
	ruleCmd.AddGroup(&ruleGroup)
	rootCmd.AddCommand(ruleCmd)

	// rule arp
	arpCmd.PersistentFlags().Var(&F.SpoofARPReplyAddr, "spoof-arp-reply", "Target MAC for ARP-Reply spoofing")
	arpCmd.AddGroup(&ruleGroup)
	addSubCommands(arpCmd, rootCmd, ruleCmd)

	// rule tcp
	tcpCmd.PersistentFlags().BoolVar(&F.TCP.SpoofHandshake, "spoof-handshake", false, "Target for TCP handshake spoofing (SYN/ACK)")
	tcpCmd.PersistentFlags().BoolVar(&F.TCP.ResetHandshake, "reset-handshake", false, "Target for TCP handshake reseting (RST/ACK)")
	tcpCmd.AddGroup(&ruleGroup)
	setCommandFlagsPorts(tcpCmd)
	addSubCommands(tcpCmd, rootCmd, ruleCmd)

	// rule udp
	udpCmd.AddGroup(&ruleGroup)
	setCommandFlagsPorts(udpCmd)
	addSubCommands(udpCmd, rootCmd, ruleCmd)

	// rule icmp
	icmpCmd.PersistentFlags().BoolVar(&F.ICMP.SpoofEchoReply, "spoof-echo-reply", false, "Target for ICMP Echo Reply spoofing​​")
	icmpCmd.AddGroup(&ruleGroup)
	setCommandFlagsPorts(icmpCmd)
	addSubCommands(icmpCmd, rootCmd, ruleCmd)

	// rule http
	httpCmd.PersistentFlags().StringVar(&F.Method, "method", "", "HTTP request method")
	httpCmd.PersistentFlags().StringVar(&F.URI, "uri", "", "HTTP request uri")
	httpCmd.PersistentFlags().StringVar(&F.Version, "version", "", "HTTP request version, (e.g. 1.1)")
	httpCmd.PersistentFlags().StringVar(&F.Host, "host", "", "HTTP request host")
	addSubCommands(httpCmd, rootCmd, ruleCmd, tcpCmd)

	// operation commands
	// each command MUST include these operations.
	setOpAddListSubCommands(ruleCmd, arpCmd, tcpCmd, udpCmd, icmpCmd, httpCmd)
	setOpGetDeleteSubCommands(ruleCmd)
}

func setCommandFlagsPorts(cmd *cobra.Command) {
	cmd.PersistentFlags().Var(&F.SrcPortRange, "sports", "Source port range (e.g. 80 or 1:1024)")
	cmd.PersistentFlags().Var(&F.DstPortRange, "dports", "Destionation port range (e.g. 80 or 1:1024)")
	cmd.PersistentFlags().Var(&F.SrcMultiPort, "multiport-sports", "Source multiports (e.g. 80,443)")
	cmd.PersistentFlags().Var(&F.DstMultiPort, "multiport-dports", "Destination multiports (e.g. 80,443)")
}

func addSubCommands(subCmd *cobra.Command, cmds ...*cobra.Command) {
	for _, cmd := range cmds {
		cmd.AddCommand(subCmd)
	}
}
