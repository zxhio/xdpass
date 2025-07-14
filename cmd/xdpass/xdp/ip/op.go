package ip

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/api"
	"github.com/zxhio/xdpass/internal/model"
	"github.com/zxhio/xdpass/pkg/netaddr"
	"github.com/zxhio/xdpass/pkg/utils"
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
		var (
			attachements []api.AttachmentIP
			total        int
		)
		if listAll {
			listPage = 1
			listLimit = 100
			for {
				resp, err := utils.NewHTTPRequestMessage[api.QueryIPResp](
					api.PathXDPIP,
					api.GetBodyData,
					utils.WithReqAddr(api.DefaultAPIAddr),
					utils.WithReqQuery(api.QueryPage{Page: listPage, Limit: listLimit}.ToQuery()),
					utils.WithReqQueryKV("attachment-id", iface),
					utils.WithReqQueryKV("action", action),
				)
				utils.CheckErrorAndExit(err, "Query ips failed")

				for _, a := range resp.Data {
					for _, ac := range a.Actions {
						total += len(ac.IPs)
					}
				}
				attachements = append(attachements, resp.Data...)
				if total >= int(resp.Total) {
					break
				}
				listPage++
			}
		} else {
			resp, err := utils.NewHTTPRequestMessage[api.QueryIPResp](
				api.PathXDPIP,
				api.GetBodyData,
				utils.WithReqAddr(api.DefaultAPIAddr),
				utils.WithReqQuery(api.QueryPage{Page: listPage, Limit: listLimit}.ToQuery()),
				utils.WithReqQueryKV("attachment-id", iface),
				utils.WithReqQueryKV("action", action),
			)
			utils.CheckErrorAndExit(err, "Query ips failed")
			attachements = resp.Data
		}

		data := [][]any{}
		for _, a := range attachements {
			for _, ai := range a.Actions {
				for _, ip := range ai.IPs {
					data = append(data, []any{a.Name, strings.ToUpper(string(ai.Action)), ip})
				}
			}
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
		table.Header("ID", "Action", "IP")
		table.Bulk(data)
		table.Render()
	},
}

var addCmd = cobra.Command{
	Use:   "add",
	Short: "Add ip for XDP program",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ip, err := netaddr.NewIPv4PrefixFromStr(args[0])
		utils.CheckErrorAndExit(err, "Invalid ip")

		req := api.AddIPReq{Attachments: []api.AttachmentIP{{
			Name: iface,
			Actions: []api.XDPActionIP{{
				Action: model.XDPAction(action),
				IPs:    []netaddr.IPv4Prefix{ip},
			}},
		}}}
		data, err := json.Marshal(req)
		utils.CheckErrorAndExit(err, "json.Marshal")

		_, err = utils.NewHTTPRequestMessage[api.AddIPResp](
			api.PathXDPIP,
			api.GetBodyData,
			utils.WithReqAddr(api.DefaultAPIAddr),
			utils.WithReqMethod(http.MethodPost),
			utils.WithReqBody(bytes.NewBuffer(data)),
		)
		utils.CheckErrorAndExit(err, "Query ips failed")
	},
}

var delCmd = cobra.Command{
	Use:     "delete",
	Short:   "Delete ip for XDP program",
	Aliases: []string{"del"},
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ip, err := netaddr.NewIPv4PrefixFromStr(args[0])
		utils.CheckErrorAndExit(err, "Invalid ip: %s", args[0])

		req := api.DeleteIPReq{
			AttachmentName: iface,
			Action:         model.XDPAction(action),
			IP:             ip,
		}
		data, err := json.Marshal(req)
		utils.CheckErrorAndExit(err, "json.Marshal")

		_, err = utils.NewHTTPRequestMessage[api.DeleteIPResp](
			api.PathXDPIP,
			api.GetBodyData,
			utils.WithReqMethod(http.MethodDelete),
			utils.WithReqAddr(api.DefaultAPIAddr),
			utils.WithReqBody(bytes.NewBuffer(data)),
		)
		utils.CheckErrorAndExit(err, "Query ips failed")
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
