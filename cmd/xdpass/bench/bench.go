package bench

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/bench"
	"github.com/zxhio/xdpass/pkg/utils"
)

var benchCmd = cobra.Command{
	Use:     "bench",
	Short:   "Packets transmit benchmark",
	Aliases: []string{"b"},
}

var tcpCmd = cobra.Command{
	Use:   "tcp",
	Short: "Packets transmit benchmark for TCP",
	Run: func(cmd *cobra.Command, args []string) {
		runTxBenchmark(bench.WithLayerTCP(&tcp))
	},
}

var udpCmd = cobra.Command{
	Use:   "udp",
	Short: "Packets transmit benchmark for UDP",
	Run: func(cmd *cobra.Command, args []string) {
		runTxBenchmark(bench.WithLayerUDP(&udp))
	},
}

var icmpCmd = cobra.Command{
	Use:   "icmp",
	Short: "Packets transmit benchmark for ICMP",
	Run: func(cmd *cobra.Command, args []string) {
		runTxBenchmark(bench.WithLayerICMP(&icmp))
	},
}

var (
	ifaceName    string
	total        int
	batch        uint32
	rateLimit    int
	statsDur     time.Duration
	cores        []int
	queues       []uint
	bindCopy     bool
	bindZeroCopy bool

	ether bench.LayerEthernet
	ipv4  bench.LayerIPv4
	vlan  bench.LayerVLAN
	tcp   bench.LayerTCP
	icmp  bench.LayerICMP
	udp   bench.LayerUDP
)

func init() {
	disableSort(&benchCmd)
	benchCmd.PersistentFlags().IntVarP(&total, "total", "n", -1, "Transmit packet total, -1 unlimited")
	benchCmd.PersistentFlags().Uint32VarP(&batch, "batch", "b", 64, "Transmit packet batch size")
	benchCmd.PersistentFlags().IntVarP(&rateLimit, "rate-limit", "r", -1, "Packet send rate limit (s), -1 unlimited")
	benchCmd.PersistentFlags().StringVarP(&ifaceName, "interface", "i", "", "Interface name")
	benchCmd.PersistentFlags().DurationVarP(&statsDur, "stats-dur", "D", 0, "Dump stats duration")
	benchCmd.PersistentFlags().IntSliceVarP(&cores, "cores", "c", []int{}, "Affinity cpu cores")
	benchCmd.PersistentFlags().UintSliceVarP(&queues, "queues", "q", []uint{}, "Interface queues")
	benchCmd.PersistentFlags().BoolVar(&bindCopy, "xdp-copy", false, "Force copy mode")
	benchCmd.PersistentFlags().BoolVar(&bindZeroCopy, "xdp-zero-copy", false, "Force zero copy mode")

	// L2
	benchCmd.PersistentFlags().Var(&ether.SrcMAC, "smac", "Source mac address")
	benchCmd.PersistentFlags().Var(&ether.DstMAC, "dmac", "Destionation mac address")
	benchCmd.PersistentFlags().Uint16Var(&vlan.ID, "vlan", 0, "VLAN id")

	// L3
	benchCmd.PersistentFlags().IPVarP(&ipv4.SrcIPv4, "source", "s", nil, "Source ip address")
	benchCmd.PersistentFlags().IPVarP(&ipv4.DstIPv4, "destination", "d", nil, "Destionation ip address")
	benchCmd.PersistentFlags().Uint8Var(&ipv4.TTL, "ttl", 97, "Time to live")
	benchCmd.MarkPersistentFlagRequired("destination")

	// TCP
	disableSort(&tcpCmd)
	setCommandFlagsPort(&tcpCmd, &tcp.LayerPorts)
	tcpCmd.Flags().BoolVarP(&tcp.SYN, "syn", "S", false, "TCP flag SYN")
	tcpCmd.Flags().BoolVar(&tcp.ACK, "ack", false, "TCP flag ACK")
	tcpCmd.Flags().BoolVarP(&tcp.PSH, "psh", "P", false, "TCP flag PSH")
	tcpCmd.Flags().BoolVarP(&tcp.RST, "rst", "R", false, "TCP flag RST")
	tcpCmd.Flags().BoolVarP(&tcp.FIN, "fin", "F", false, "TCP flag FIN")
	tcpCmd.Flags().Uint32Var(&tcp.Seq, "seq", 0, "TCP sequence")
	tcpCmd.Flags().StringVar(&tcp.Payload, "payload", "", "TCP payload")
	tcpCmd.Flags().StringVar(&tcp.PayloadPath, "payload-path", "", "TCP payload path")
	benchCmd.AddCommand(&tcpCmd)

	// UDP
	disableSort(&udpCmd)
	setCommandFlagsPort(&udpCmd, &udp.LayerPorts)
	udpCmd.Flags().StringVar(&udp.Payload, "payload", "", "UDP payload")
	udpCmd.Flags().StringVar(&udp.PayloadPath, "payload-path", "", "UDP payload path")
	benchCmd.AddCommand(&udpCmd)

	// ICMP
	disableSort(&icmpCmd)
	icmpCmd.Flags().Uint16Var(&icmp.ID, "id", 0, "ICMPv4 echo request id")
	icmpCmd.Flags().Uint16Var(&icmp.Seq, "seq", 0, "ICMPv4 echo request sequence")
	benchCmd.AddCommand(&icmpCmd)
}

func setCommandFlagsPort(cmd *cobra.Command, p *bench.LayerPorts) {
	cmd.Flags().Uint16Var(&p.SPort, "sport", 0, "Source port")
	cmd.Flags().Uint16Var(&p.DPort, "dport", 0, "Destionation port")
}

func runTxBenchmark(opts ...bench.LayerOpt) {
	data, err := bench.MakePacketData(&ifaceName, &ether, &ipv4, opts...)
	utils.CheckErrorAndExit(err, "Make packet tx data failed")

	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	fmt.Println(pkt.String())
	fmt.Printf("PACKET hexdump %d bytes\n%v\n", len(data), hex.Dump(data))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGUSR1)
	go func() {
		sig := <-sigCh
		fmt.Println(sig.String())
		cancel()
	}()

	err = bench.Benchmark(ctx,
		ifaceName, data,
		bench.WithBenchmarkN(total, batch),
		bench.WithBenchmarkRateLimit(rateLimit),
		bench.WithBenchmarkStatsDur(statsDur),
		bench.WithBenchmarkCPUCores(cores),
		bench.WithBenchmarkQueues(queues),
		bench.WithBenchmarkXDPBindMode(bindCopy, bindZeroCopy),
	)
	utils.CheckErrorAndExit(err, "Run tx benchmark failed")
}

func disableSort(cmds ...*cobra.Command) {
	for _, cmd := range cmds {
		// both
		cmd.InheritedFlags().SortFlags = false
		cmd.PersistentFlags().SortFlags = false
		cmd.Flags().SortFlags = false
	}
}

func Export(parent *cobra.Command) {
	parent.AddCommand(&benchCmd)
}
