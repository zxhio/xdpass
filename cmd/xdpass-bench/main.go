package main

import (
	"context"
	"encoding/hex"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type benchOpt struct {
	IfaceName        string
	QueueId          int
	BenchNum         int
	BatchSize        uint32
	RateLimit        int
	RateLimitPrecStr string
	Cores            []int
	Stats            uint
	layerOpt
}

var opt benchOpt

var root = cobra.Command{
	Use:   "xdpass-bench",
	Short: "TCP/IP packet maker in Go",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var tcp = &cobra.Command{
	Use:   "tcp",
	Short: "Send TCP packets",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := makePacketData(opt.IfaceName, &opt.layerOpt, l4MakerTCP{})
		if err != nil {
			return err
		}
		logrus.Infof("Packet hexdump %d bytes:\n%v", len(data), hex.Dump(data))
		return runTxBenchmark(context.Background(), &opt, data)
	},
}

var icmpv4 = &cobra.Command{
	Use:   "icmp",
	Short: "Send ICMPv4 echo request packets",
	RunE: func(cmd *cobra.Command, _ []string) error {
		data, err := makePacketData(opt.IfaceName, &opt.layerOpt, l4MakerICMPv4{})
		if err != nil {
			return err
		}
		logrus.Infof("Packet hexdump %d bytes:\n%v", len(data), hex.Dump(data))
		return runTxBenchmark(context.Background(), &opt, data)
	},
}

var udp = &cobra.Command{
	Use:   "udp",
	Short: "Send UDP packets",
	RunE: func(cmd *cobra.Command, _ []string) error {
		data, err := makePacketData(opt.IfaceName, &opt.layerOpt, l4MakerUDP{})
		if err != nil {
			return err
		}
		logrus.Infof("Packet hexdump %d bytes:\n%v", len(data), hex.Dump(data))
		return runTxBenchmark(context.Background(), &opt, data)
	},
}

func init() {
	root.PersistentFlags().StringVarP(&opt.IfaceName, "iface", "i", "", "Interface name")
	root.PersistentFlags().IntVarP(&opt.QueueId, "queue-id", "q", -1, "Interface queue id, -1 all queue id")
	root.PersistentFlags().StringVar(&opt.SrcMACStr, "src-mac", "", "MAC source address")
	root.PersistentFlags().StringVar(&opt.DstMACStr, "dst-mac", "", "MAC destination address")
	root.PersistentFlags().Uint16Var(&opt.VlanId, "vlan", 0, "Vlan id")
	root.PersistentFlags().StringVar(&opt.SrcIPStr, "src-ip", "", "IPv4 source address")
	root.PersistentFlags().StringVar(&opt.DstIPStr, "dst-ip", "", "IPv4 destination address")
	root.PersistentFlags().IntVarP(&opt.BenchNum, "num", "n", 1, "Packet send num")
	root.PersistentFlags().Uint32Var(&opt.BatchSize, "batch-size", 64, "Packet send batch size")
	root.PersistentFlags().IntVar(&opt.RateLimit, "rate-limit", 1, "Packet send rate limit (s), -1 not limit")
	root.PersistentFlags().StringVar(&opt.RateLimitPrecStr, "rate-limit-prec", "low", "Packet send rate limit precision, low|mid|high")
	root.PersistentFlags().UintVarP(&opt.Stats, "stats", "s", 0, "Statistics output duration (s)")
	root.PersistentFlags().IntSliceVar(&opt.Cores, "cpu", []int{0}, "Affinity cpu, -1 not set")
	root.MarkFlagRequired("iface")
	root.MarkFlagRequired("dst-ip")

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
	tcp.Flags().StringVar(&opt.tcp.PayloadHex, "payload-hex", "", "TCP hex payload")

	// ICMP
	icmpv4.Flags().Uint16Var(&opt.icmp4.Id, "id", 0, "ICMPv4 echo request id")
	icmpv4.Flags().Uint16Var(&opt.icmp4.Seq, "seq", 0, "ICMPv4 echo request sequence")

	// UDP
	udp.Flags().Uint16Var(&opt.udp.SrcPort, "src-port", 0, "UDP source port")
	udp.Flags().Uint16Var(&opt.udp.DstPort, "dst-port", 0, "UDP destination port")
	udp.Flags().StringVar(&opt.udp.Payload, "payload", "", "UDP payload")
	udp.Flags().StringVar(&opt.udp.PayloadHex, "payload-hex", "", "UDP hex payload")

	root.AddCommand(tcp)
	root.AddCommand(icmpv4)
	root.AddCommand(udp)
}

func main() {
	err := root.Execute()
	if err != nil {
		panic(err)
	}
}
