package attachment

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/zxhio/xdpass/internal/api"
	"github.com/zxhio/xdpass/pkg/humanize"
	"github.com/zxhio/xdpass/pkg/netutil"
)

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

func displayStats(ifaces []*api.QueryAttachmentStatsResp, fields []StatsFields, prev map[string]netutil.Statistics) {
	sum := struct {
		netutil.Statistics
		netutil.StatisticsRate
		numQueues int
	}{}

	statsKey := func(iface string, queueID uint32) string {
		return fmt.Sprintf("%s:%d", iface, queueID)
	}

	tbl := tablewriter.NewTable(os.Stdout,
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Borders: tw.BorderNone,
			Settings: tw.Settings{
				Separators: tw.SeparatorsNone,
				// Lines:      tw.LinesNone,
			},
		})),
		tablewriter.WithRowAlignment(tw.AlignCenter),
	)
	headers := []string{"interface", "queue"}
	for _, field := range fields {
		headers = append(headers, field.Headers()...)
	}
	tbl.Header(headers)

	for _, iface := range ifaces {
		for _, st := range iface.Queues {
			stat := st.Stats
			rate := stat.Rate(prev[statsKey(iface.Name, st.QueueID)])
			prev[statsKey(iface.Name, st.QueueID)] = stat

			row := []string{iface.Name, fmt.Sprintf("%d", st.QueueID)}
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
	tbl.Footer(row)
	tbl.Render()
	fmt.Println()

}
