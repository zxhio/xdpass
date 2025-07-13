package ip

import (
	"bytes"
	"encoding/json"
	"fmt"
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
				resp, err := api.NewReqMessage[api.QueryIPResp](
					api.PathXDPIP,
					api.WithReqAddr(api.DefaultAPIAddr),
					api.WithReqQuery(
						api.QueryPage{Page: listPage, Limit: listLimit}.ToQuery(),
						fmt.Sprintf("attachment-id=%s", ipAttachmentID),
						fmt.Sprintf("action=%s", ipAction),
					),
				)
				utils.CheckErrorAndExit(err, "Query ips failed")

				for _, a := range resp.Attachments {
					for _, ac := range a.Actions {
						total += len(ac.IPs)
					}
				}
				attachements = append(attachements, resp.Attachments...)
				if total >= int(resp.Total) {
					break
				}
				listPage++
			}
		} else {
			resp, err := api.NewReqMessage[api.QueryIPResp](
				api.PathXDPIP,
				api.WithReqAddr(api.DefaultAPIAddr),
				api.WithReqQuery(
					api.QueryPage{Page: listPage, Limit: listLimit}.ToQuery(),
					fmt.Sprintf("attachment-id=%s", ipAttachmentID),
					fmt.Sprintf("action=%s", ipAction),
				),
			)
			utils.CheckErrorAndExit(err, "Query ips failed")
			attachements = resp.Attachments
		}

		data := [][]any{}
		for _, a := range attachements {
			for _, ai := range a.Actions {
				for _, ip := range ai.IPs {
					data = append(data, []any{a.ID, strings.ToUpper(string(ai.Action)), ip})
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
			ID: ipAttachmentID,
			Actions: []api.XDPActionIP{{
				Action: model.XDPAction(ipAction),
				IPs:    []netaddr.IPv4Prefix{ip},
			}},
		}}}
		data, err := json.Marshal(req)
		utils.CheckErrorAndExit(err, "json.Marshal")

		_, err = api.NewReqMessage[api.AddIPResp](
			api.PathXDPIP,
			api.WithReqAddr(api.DefaultAPIAddr),
			api.WithReqMethod(http.MethodPost),
			api.WithReqBody(bytes.NewBuffer(data)),
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
			AttachmentID: ipAttachmentID,
			Action:       model.XDPAction(ipAction),
			IP:           ip,
		}
		data, err := json.Marshal(req)
		utils.CheckErrorAndExit(err, "json.Marshal")

		_, err = api.NewReqMessage[api.DeleteIPResp](
			api.PathXDPIP,
			api.WithReqMethod(http.MethodDelete),
			api.WithReqAddr(api.DefaultAPIAddr),
			api.WithReqBody(bytes.NewBuffer(data)),
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
