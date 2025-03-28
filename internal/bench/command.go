package bench

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
)

type benchOpt struct {
	ifaceName     string
	queueID       int
	n             int
	batch         uint32
	rateLimit     int
	rateLimitPrec rateLimitPrecision
	cores         []int
	statsDur      uint
	bindCopy      bool
	bindZeroCopy  bool
	layerOpt
}

var opt benchOpt

var benchCmd = cobra.Command{
	Use:   "bench",
	Short: "Packets transmit benchmark",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var tcp = &cobra.Command{
	Use:   "tcp",
	Short: "Transmit TCP packets",
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()

		data, err := makePacketData(opt.ifaceName, &opt.layerOpt, l4MakerTCP{})
		if err != nil {
			return err
		}
		return runTxBenchmark(context.Background(), &opt, data)
	},
}

var icmpv4 = &cobra.Command{
	Use:   "icmp",
	Short: "Transmit ICMPv4 echo request packets",
	RunE: func(cmd *cobra.Command, _ []string) error {
		commands.SetVerbose()

		data, err := makePacketData(opt.ifaceName, &opt.layerOpt, l4MakerICMPv4{})
		if err != nil {
			return err
		}
		return runTxBenchmark(context.Background(), &opt, data)
	},
}

var udp = &cobra.Command{
	Use:   "udp",
	Short: "Transmit UDP packets",
	RunE: func(cmd *cobra.Command, _ []string) error {
		commands.SetVerbose()

		data, err := makePacketData(opt.ifaceName, &opt.layerOpt, l4MakerUDP{})
		if err != nil {
			return err
		}
		return runTxBenchmark(context.Background(), &opt, data)
	},
}

func init() {
	commands.SetFlagsInterface(benchCmd.PersistentFlags(), &opt.ifaceName)
	benchCmd.PersistentFlags().IntVarP(&opt.queueID, "queue-id", "q", -1, "Interface queue id, -1 all queues")
	benchCmd.PersistentFlags().BoolVar(&opt.bindCopy, "xdp-copy", false, "Force copy mode")
	benchCmd.PersistentFlags().BoolVar(&opt.bindZeroCopy, "xdp-zero-copy", false, "Force zero copy mode")
	benchCmd.PersistentFlags().IntVarP(&opt.n, "total", "n", -1, "Transmit packet total, -1 unlimited")
	benchCmd.PersistentFlags().Uint32VarP(&opt.batch, "batch", "b", 64, "Transmit packet batch size")
	benchCmd.PersistentFlags().IntVarP(&opt.rateLimit, "rate-limit", "r", -1, "Packet send rate limit (s), -1 unlimited")
	benchCmd.PersistentFlags().VarP(&opt.rateLimitPrec, "rate-limit-prec", "p", "Packet send rate limit precision, low|mid|high")
	benchCmd.PersistentFlags().UintVarP(&opt.statsDur, "stats-dur", "s", 0, "Statistics output duration (s)")
	benchCmd.PersistentFlags().IntSliceVarP(&opt.cores, "cores", "c", []int{-1}, "Affinity cpu cores, -1 not set, cores must <= queues")

	// L2
	benchCmd.PersistentFlags().StringVar(&opt.SrcMACStr, "src-mac", "", "MAC source address")
	benchCmd.PersistentFlags().StringVar(&opt.DstMACStr, "dst-mac", "", "MAC destination address")
	benchCmd.PersistentFlags().Uint16Var(&opt.VlanId, "vlan-id", 0, "Vlan id")

	// L3
	benchCmd.PersistentFlags().StringVar(&opt.SrcIPStr, "src-ip", "", "IPv4 source address")
	benchCmd.PersistentFlags().StringVar(&opt.DstIPStr, "dst-ip", "", "IPv4 destination address")

	// TCP
	tcp.Flags().BoolVarP(&opt.tcp.SYN, "SYN", "S", false, "TCP flags SYN")
	tcp.Flags().BoolVarP(&opt.tcp.ACK, "ACK", "", false, "TCP flags ACK")
	tcp.Flags().BoolVarP(&opt.tcp.PSH, "PSH", "P", false, "TCP flags PSH")
	tcp.Flags().BoolVarP(&opt.tcp.RST, "RST", "R", false, "TCP flags RST")
	tcp.Flags().BoolVarP(&opt.tcp.FIN, "FIN", "F", false, "TCP flags FIN")
	tcp.Flags().Uint16Var(&opt.tcp.SrcPort, "src-port", 0, "TCP source port")
	tcp.Flags().Uint16Var(&opt.tcp.DstPort, "dst-port", 0, "TCP destination port")
	tcp.Flags().Uint32Var(&opt.tcp.Seq, "seq", 0, "TCP sequence")
	tcp.Flags().StringVar(&opt.tcp.Payload, "payload", "", "TCP payload")
	tcp.Flags().StringVar(&opt.tcp.PayloadPath, "payload-path", "", "TCP payload path")

	// ICMP
	icmpv4.Flags().Uint16Var(&opt.icmp4.Id, "id", 0, "ICMPv4 echo request id")
	icmpv4.Flags().Uint16Var(&opt.icmp4.Seq, "seq", 0, "ICMPv4 echo request sequence")

	// UDP
	udp.Flags().Uint16Var(&opt.udp.SrcPort, "src-port", 0, "UDP source port")
	udp.Flags().Uint16Var(&opt.udp.DstPort, "dst-port", 0, "UDP destination port")
	udp.Flags().StringVar(&opt.udp.Payload, "payload", "", "UDP payload")
	udp.Flags().StringVar(&opt.udp.PayloadPath, "payload-path", "", "UDP payload path")

	benchCmd.AddCommand(tcp)
	benchCmd.AddCommand(icmpv4)
	benchCmd.AddCommand(udp)

	commands.Register(&benchCmd)
}
