package rule

import (
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/rule"
	"github.com/zxhio/xdpass/pkg/fastpkt"
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
	FlagSYN bool
	FlagACK bool
	FlagPSH bool
	FlagRST bool
	FlagFIN bool

	// Target
	SpoofSYNACK bool
	SpoofRSTACK bool
	SpoofFINACK bool
	SpoofPSHACK bool
	SpoofACK    bool
}

type RuleICMPFlags struct {
	SpoofEchoReply bool
}

type RuleHTTPFlags struct {
	Method        string
	URI           string
	Version       string
	Host          string
	SpoofNotFound bool
}

var (
	F RuleFlags
	R rule.Rule
)

var group = cobra.Group{ID: "rule", Title: "Rule-Based-Protocol Commands:"}

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
	GroupID: group.ID,
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
	GroupID: group.ID,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		R.Matchs = append(R.Matchs, rule.MatchTCP{})

		var tf fastpkt.TCPFlags
		if F.TCP.FlagSYN {
			tf.Set(fastpkt.TCPFlagSYN)
		}
		if F.TCP.FlagACK {
			tf.Set(fastpkt.TCPFlagACK)
		}
		if F.TCP.FlagPSH {
			tf.Set(fastpkt.TCPFlagPSH)
		}
		if F.TCP.FlagRST {
			tf.Set(fastpkt.TCPFlagRST)
		}
		if F.TCP.FlagFIN {
			tf.Set(fastpkt.TCPFlagFIN)
		}
		if tf != 0 {
			R.Matchs = append(R.Matchs, rule.MatchTCPFlags(tf))
		}

		if F.TCP.SpoofSYNACK {
			R.Target = rule.TargetTCPSpoofSYNACK{}
		} else if F.TCP.SpoofRSTACK {
			R.Target = rule.TargetTCPSpoofRSTACK{}
		} else if F.TCP.SpoofFINACK {
			R.Target = rule.TargetTCPSpoofFINACK{}
		} else if F.TCP.SpoofPSHACK {
			R.Target = rule.TargetTCPSpoofPSHACK{}
		} else if F.TCP.SpoofACK {
			R.Target = rule.TargetTCPSpoofACK{}
		}
	},
}

var udpCmd = &cobra.Command{
	Use:     "udp",
	Short:   "Matches UDP layer fields and specifies the target",
	Aliases: []string{"rule udp"},
	GroupID: group.ID,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		R.Matchs = append(R.Matchs, rule.MatchUDP{})
	},
}

var icmpCmd = &cobra.Command{
	Use:     "icmp",
	Short:   "Matches ICMP layer fields and specifies the target",
	Aliases: []string{"rule icmp"},
	GroupID: group.ID,
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
	GroupID: group.ID,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		R.Matchs = append(R.Matchs, rule.MatchHTTP{})
		if F.SpoofNotFound {
			R.Target = rule.TargetHTTPRespSpoofNotFound{}
		}
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
	ruleCmd.PersistentFlags().BoolVar(&F.MirrorStdout, "mirror-stdout", false, "[Target] Mirror traffic to stdout")
	ruleCmd.PersistentFlags().StringVar(&F.MirrorTap, "mirror-tap", "", "[Target] Mirror traffic to tap device")
	ruleCmd.AddGroup(&group)

	// rule arp
	arpCmd.PersistentFlags().Var(&F.SpoofARPReplyAddr, "spoof-arp-reply", "[Target] MAC ARP-Reply spoofing")

	// rule tcp
	tcpCmd.PersistentFlags().BoolVarP(&F.TCP.FlagSYN, "flag-syn", "S", false, "TCP flag SYN")
	tcpCmd.PersistentFlags().BoolVar(&F.TCP.FlagACK, "flag-ack", false, "TCP flag ACK")
	tcpCmd.PersistentFlags().BoolVarP(&F.TCP.FlagPSH, "flag-psh", "P", false, "TCP flag PSH")
	tcpCmd.PersistentFlags().BoolVarP(&F.TCP.FlagRST, "flag-rst", "R", false, "TCP flag RST")
	tcpCmd.PersistentFlags().BoolVarP(&F.TCP.FlagFIN, "flag-fin", "F", false, "TCP flag FIN")
	tcpCmd.PersistentFlags().BoolVar(&F.TCP.SpoofSYNACK, "spoof-syn-ack", false, "[Target] TCP SYN/ACK reply spoofing")
	tcpCmd.PersistentFlags().BoolVar(&F.TCP.SpoofRSTACK, "spoof-rst-ack", false, "[Target] TCP RST/ACK reply spoofing")
	tcpCmd.PersistentFlags().BoolVar(&F.TCP.SpoofPSHACK, "spoof-psh-ack", false, "[Target] TCP PSH/ACK reply spoofing")
	tcpCmd.PersistentFlags().BoolVar(&F.TCP.SpoofFINACK, "spoof-fin-ack", false, "[Target] TCP FIN/ACK reply spoofing")
	tcpCmd.PersistentFlags().BoolVar(&F.TCP.SpoofACK, "spoof-ack", false, "[Target] TCP ACK reply spoofing")
	tcpCmd.AddGroup(&group)
	setCommandFlagsPorts(tcpCmd)

	// rule udp
	setCommandFlagsPorts(udpCmd)

	// rule icmp
	icmpCmd.PersistentFlags().BoolVar(&F.ICMP.SpoofEchoReply, "spoof-echo-reply", false, "[Target] ICMP Echo-Reply spoofing")
	setCommandFlagsPorts(icmpCmd)

	// rule http
	httpCmd.PersistentFlags().StringVar(&F.Method, "method", "", "HTTP request method")
	httpCmd.PersistentFlags().StringVar(&F.URI, "uri", "", "HTTP request uri")
	httpCmd.PersistentFlags().StringVar(&F.Version, "version", "", "HTTP request version, (e.g. 1.1)")
	httpCmd.PersistentFlags().StringVar(&F.Host, "host", "", "HTTP request host")
	httpCmd.PersistentFlags().BoolVar(&F.SpoofNotFound, "spoof-not-found", false, "[Target] HTTP 404 not found response spoofing")
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

func Export(parent *cobra.Command) {
	// operation commands
	// each command MUST include these operations.
	setOpCommandsWithoutID(arpCmd, tcpCmd, udpCmd, icmpCmd, httpCmd)
	setOpCommands(ruleCmd)

	parent.AddGroup(&group)

	// Note:
	// cmd.Parent will be modified after call cobra.AppendCommand()
	// Some commands (e.g. tcp/udp) needs to inherit the flags of the rule command, so the parent cannot be modified
	addSubCommands(ruleCmd, parent)
	addSubCommands(arpCmd, parent, ruleCmd)
	addSubCommands(tcpCmd, parent, ruleCmd)
	addSubCommands(udpCmd, parent, ruleCmd)
	addSubCommands(icmpCmd, parent, ruleCmd)
	addSubCommands(httpCmd, parent, ruleCmd, tcpCmd)
}
