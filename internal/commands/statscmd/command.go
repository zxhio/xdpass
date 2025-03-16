package statscmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/exports"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/humanize"
	"github.com/zxhio/xdpass/pkg/netutil"
)

var statsCommand = &cobra.Command{
	Use:   protos.TypeStats.String(),
	Short: "Display a live stream of network traffic statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		return StatsCommandClient{}.DoReq(opt)
	},
}

func init() {
	commands.SetFlagsInterface(statsCommand.Flags(), &opt.Interface)
	statsCommand.Flags().DurationVarP(&opt.StatsDur, "duration", "d", time.Second*3, "Statistics duration")
	statsCommand.Flags().BoolVarP(&opt.ShowPackets, "packets", "p", true, "Show packets")
	statsCommand.Flags().BoolVarP(&opt.ShowPps, "pps", "P", true, "Show pps")
	statsCommand.Flags().BoolVarP(&opt.ShowBytes, "bytes", "b", true, "Show bytes")
	statsCommand.Flags().BoolVarP(&opt.ShowBps, "bps", "B", true, "Show bps")
	statsCommand.Flags().BoolVarP(&opt.ShowIops, "iops", "I", false, "Show iops")
	statsCommand.Flags().BoolVarP(&opt.ShowErrIops, "err-iops", "E", false, "Show error iops")
	statsCommand.Flags().BoolVarP(&opt.ShowAll, "all", "a", false, "Show all")
	commands.Register(statsCommand)
}

type StatsOpt struct {
	Interface   string
	StatsDur    time.Duration
	ShowAll     bool
	ShowPackets bool
	ShowPps     bool
	ShowBytes   bool
	ShowBps     bool
	ShowIops    bool
	ShowErrIops bool
}

type StatsFields interface {
	Headers() []string
	Values(stat netutil.Statistics, rate netutil.StatisticsRate) []string
}

type StatsFieldsQueues struct{}

type StatsFieldsPackets struct{}

func (StatsFieldsPackets) Headers() []string { return []string{"rx_pkts", "tx_pkts"} }
func (StatsFieldsPackets) Values(stat netutil.Statistics, _ netutil.StatisticsRate) []string {
	return []string{
		fmt.Sprintf("%d", stat.RxPackets),
		fmt.Sprintf("%d", stat.TxPackets),
	}
}

type StatsFieldsPps struct{}

func (StatsFieldsPps) Headers() []string { return []string{"rx_pps", "tx_pps"} }
func (StatsFieldsPps) Values(stat netutil.Statistics, rate netutil.StatisticsRate) []string {
	return []string{
		fmt.Sprintf("%.0f", rate.RxPPS),
		fmt.Sprintf("%.0f", rate.TxPPS),
	}
}

type StatsFieldsBytes struct{}

func (StatsFieldsBytes) Headers() []string { return []string{"rx_bytes", "tx_bytes"} }
func (StatsFieldsBytes) Values(stat netutil.Statistics, _ netutil.StatisticsRate) []string {
	return []string{
		humanize.Bytes(int(stat.RxBytes)),
		humanize.Bytes(int(stat.TxBytes)),
	}
}

type StatsFieldsBps struct{}

func (StatsFieldsBps) Headers() []string { return []string{"rx_bps", "tx_bps"} }
func (StatsFieldsBps) Values(stat netutil.Statistics, rate netutil.StatisticsRate) []string {
	return []string{
		humanize.BitsRate(int(rate.RxBPS)),
		humanize.BitsRate(int(rate.TxBPS)),
	}
}

type StatsFieldsIops struct{}

func (StatsFieldsIops) Headers() []string { return []string{"rx_iops", "tx_iops"} }
func (StatsFieldsIops) Values(stat netutil.Statistics, rate netutil.StatisticsRate) []string {
	return []string{
		fmt.Sprintf("%.0f", rate.RxIOPS),
		fmt.Sprintf("%.0f", rate.TxIOPS),
	}
}

type StatsFieldsErrIops struct{}

func (StatsFieldsErrIops) Headers() []string { return []string{"rx_err_iops", "tx_err_iops"} }
func (StatsFieldsErrIops) Values(stat netutil.Statistics, rate netutil.StatisticsRate) []string {
	return []string{
		fmt.Sprintf("%.0f", rate.RxErrIOPS),
		fmt.Sprintf("%.0f", rate.TxErrIOPS),
	}
}

var opt StatsOpt

type StatsCommandClient struct{}

func (StatsCommandClient) DoReq(opt StatsOpt) error {
	fields := []StatsFields{}

	if opt.ShowAll {
		fields = append(fields, StatsFieldsPackets{})
		fields = append(fields, StatsFieldsPps{})
		fields = append(fields, StatsFieldsBytes{})
		fields = append(fields, StatsFieldsBps{})
		fields = append(fields, StatsFieldsIops{})
		fields = append(fields, StatsFieldsErrIops{})
	} else {
		if opt.ShowPackets {
			fields = append(fields, StatsFieldsPackets{})
		}
		if opt.ShowPps {
			fields = append(fields, StatsFieldsPps{})
		}
		if opt.ShowBytes {
			fields = append(fields, StatsFieldsBytes{})
		}
		if opt.ShowBps {
			fields = append(fields, StatsFieldsBps{})
		}
		if opt.ShowIops {
			fields = append(fields, StatsFieldsIops{})
		}
		if opt.ShowErrIops {
			fields = append(fields, StatsFieldsErrIops{})
		}
	}

	statsKey := func(iface string, queueID uint32) string {
		return fmt.Sprintf("%s:%d", iface, queueID)
	}
	prev := make(map[string]netutil.Statistics)

	timer := time.NewTicker(opt.StatsDur)
	for range timer.C {
		tbl := tablewriter.NewWriter(os.Stdout)
		tbl.SetAutoMergeCellsByColumnIndex([]int{0})
		tbl.SetAlignment(tablewriter.ALIGN_CENTER)

		headers := []string{"interface", "queue"}
		for _, field := range fields {
			headers = append(headers, field.Headers()...)
		}
		tbl.SetHeader(headers)

		sum := struct {
			netutil.Statistics
			netutil.StatisticsRate
			numQueues int
		}{}

		req := &protos.StatsReq{Interface: opt.Interface}
		resp, err := commands.GetMessageByAddr[protos.StatsReq, protos.StatsResp](commands.DefUnixSock, protos.TypeStats, "", req)
		if err != nil {
			return err
		}
		sort.Sort(statsSlice(resp.Interfaces))
		for _, iface := range resp.Interfaces {
			for _, queue := range iface.Queues {
				stat := queue.Statistics
				rate := stat.Rate(prev[statsKey(iface.Interface, queue.QueueID)])
				prev[statsKey(iface.Interface, queue.QueueID)] = stat

				row := []string{iface.Interface, fmt.Sprintf("%d", queue.QueueID)}
				for _, field := range fields {
					row = append(row, field.Values(stat, rate)...)
				}
				tbl.Append(row)

				sum.RxPackets += stat.RxPackets
				sum.TxPackets += stat.TxPackets
				sum.RxBytes += stat.RxBytes
				sum.TxBytes += stat.TxBytes
				sum.RxPPS += rate.RxPPS
				sum.TxPPS += rate.TxPPS
				sum.RxBPS += rate.RxBPS
				sum.TxBPS += rate.TxBPS
				sum.RxIOPS += rate.RxIOPS
				sum.TxIOPS += rate.TxIOPS
				sum.numQueues++
			}
		}

		row := []string{}
		row = append(row, "SUM", fmt.Sprintf("%d", sum.numQueues))
		for _, field := range fields {
			row = append(row, field.Values(sum.Statistics, sum.StatisticsRate)...)
		}
		tbl.SetFooter(row)
		tbl.Render()
		fmt.Println()
	}

	return nil
}

type statsSlice []protos.InterfaceStats

func (s statsSlice) Len() int           { return len(s) }
func (s statsSlice) Less(i, j int) bool { return s[i].Interface < s[j].Interface }
func (s statsSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

type StatsCommandHandle struct{}

func (StatsCommandHandle) CommandType() protos.Type {
	return protos.TypeStats
}

func (StatsCommandHandle) HandleReqData(client *commands.MessageClient, data []byte) error {
	req := &protos.StatsReq{}
	if err := json.Unmarshal(data, req); err != nil {
		return err
	}

	var apis map[string]exports.StatsAPI
	if req.Interface != "" {
		api, ok := exports.GetStatsAPI(req.Interface)
		if !ok {
			return errors.New("interface not found")
		}
		apis = map[string]exports.StatsAPI{req.Interface: api}
	} else {
		apis = exports.GetStatsAPIs()
	}

	resp := &protos.StatsResp{}
	resp.Interfaces = make([]protos.InterfaceStats, len(apis))
	for ifaceName, api := range apis {
		stats := api.GetQueueStats()
		resp.Interfaces = append(resp.Interfaces, protos.InterfaceStats{
			Interface: ifaceName,
			Queues:    stats,
		})
	}
	return commands.ResponseMessage(client, resp)
}
