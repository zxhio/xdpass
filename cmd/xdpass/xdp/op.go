package xdp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/api"
	"github.com/zxhio/xdpass/pkg/netaddr"
	"github.com/zxhio/xdpass/pkg/utils"
)

const (
	defaultAPIAddr = "http://127.0.0.1:9921"
)

var (
	listPage  int
	listLimit int
	listAll   bool
)

var listCmd = cobra.Command{
	Use:     "list",
	Short:   "List ip for XDP program",
	Aliases: []string{"ls"},
	Args:    cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		action := cmd.Parent().Name()
		utils.CheckEqualAndExit(validateAction(action), "Unsupport xdp action: %s", action)

		var ips []netaddr.IPv4Prefix
		if listAll {
			listPage = 1
			listLimit = 100
			total := 0
			for {
				resp, err := api.NewReqMessage[api.QueryIPsResp](
					api.InstantiateAPIURL(api.APIPathQueryIPsAction, map[string]string{":action": action}),
					api.WithReqAddr(defaultAPIAddr),
					api.WithReqQuery(api.QueryPage{Page: listPage, Limit: listLimit}.ToQuery()),
				)
				utils.CheckErrorAndExit(err, "Query ips failed")

				total += len(resp.Data)
				ips = append(ips, resp.Data...)
				if total >= int(resp.Total) {
					break
				}
				listPage++
			}
		} else {
			resp, err := api.NewReqMessage[api.QueryIPsResp](
				api.InstantiateAPIURL(api.APIPathQueryIPsAction, map[string]string{":action": action}),
				api.WithReqAddr(defaultAPIAddr),
				api.WithReqQuery(api.QueryPage{Page: listPage, Limit: listLimit}.ToQuery()),
			)
			utils.CheckErrorAndExit(err, "Query ips failed")
			ips = resp.Data
		}

		ss := []string{}
		for _, ip := range ips {
			ss = append(ss, ip.String())
		}
		slices.Sort(ss)

		data := [][]any{}
		for _, ip := range ss {
			data = append(data, []any{ip})
		}

		table := tablewriter.NewTable(os.Stdout,
			tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
				Borders: tw.BorderNone,
				Settings: tw.Settings{
					Separators: tw.SeparatorsNone,
					Lines:      tw.LinesNone,
				},
			})),
		)
		table.Bulk(data)
		table.Render()
	},
}

var addCmd = cobra.Command{
	Use:   "add",
	Short: "Add ip for XDP program",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		action := cmd.Parent().Name()
		utils.CheckEqualAndExit(validateAction(action), "Unsupport xdp action: %s", action)

		ip, err := netaddr.NewIPv4PrefixFromStr(args[0])
		utils.CheckErrorAndExit(err, "Invalid ip")

		data, err := json.Marshal(api.AddIPReq{IP: ip})
		utils.CheckErrorAndExit(err, "json.Marshal")

		resp, err := api.NewReqMessage[api.AddIPResp](
			api.InstantiateAPIURL(api.APIPathAddIPAction, map[string]string{":action": action}),
			api.WithReqAddr(defaultAPIAddr),
			api.WithReqMethod(http.MethodPost),
			api.WithReqBody(bytes.NewBuffer(data)),
		)
		utils.CheckErrorAndExit(err, "Query ips failed")

		fmt.Printf("Add %s to %s ips success\n", resp.IP, resp.Action)
	},
}

var delCmd = cobra.Command{
	Use:     "delete",
	Short:   "Delete ip for XDP program",
	Aliases: []string{"del"},
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		action := cmd.Parent().Name()
		utils.CheckEqualAndExit(validateAction(action), "Unsupport xdp action: %s", action)

		ip, err := netaddr.NewIPv4PrefixFromStr(args[0])
		utils.CheckErrorAndExit(err, "Invalid ip: %s", args[0])

		resp, err := api.NewReqMessage[api.DeleteIPResp](
			api.InstantiateAPIURL(api.APIPathDeleteIPAction, map[string]string{
				":action": action,
				":ip":     api.IPv4PrefixToPath(ip),
			}),
			api.WithReqMethod(http.MethodDelete),
			api.WithReqAddr(defaultAPIAddr),
		)
		utils.CheckErrorAndExit(err, "Query ips failed")

		fmt.Printf("Delete %s to %s ips success\n", resp.IP, resp.Action)
	},
}

func init() {
	listCmd.Flags().IntVar(&listPage, "page", 1, "Page number to list")
	listCmd.Flags().IntVar(&listLimit, "limit", 100, "Limit size per page")
	listCmd.Flags().BoolVarP(&listAll, "all", "a", false, "List all ip")
}

func setOpCommands(cmds ...*cobra.Command) {
	for _, cmd := range cmds {
		cmd.AddGroup(&cobra.Group{ID: "operation", Title: "Operation Commands:"})
		opCmds := []cobra.Command{addCmd, delCmd, listCmd}
		for i := range opCmds {
			sub := opCmds[i]
			sub.GroupID = "operation"
			cmd.AddCommand(&sub)
		}
	}
}

func validateAction(action string) bool {
	return slices.Contains([]api.XDPAction{
		api.XDPActionPass,
		api.XDPActionRedirect,
	}, api.XDPAction(action))
}
