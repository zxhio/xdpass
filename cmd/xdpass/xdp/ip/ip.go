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
	"github.com/zxhio/xdpass/cmd/xdpass/xdp/attachment"
	"github.com/zxhio/xdpass/internal/api"
	"github.com/zxhio/xdpass/internal/model"
	"github.com/zxhio/xdpass/pkg/netaddr"
	"github.com/zxhio/xdpass/pkg/utils"
)

var opt struct {
	Pass     bool
	Redirect bool
	Iface    string

	// list
	Page  int
	Limit int
	All   bool
}

var ipCmd = &cobra.Command{
	Use:   "ip",
	Short: "Manage ip set for XDP program",
}

var listCmd = cobra.Command{
	Use:     "list",
	Short:   "List ip for XDP program",
	Aliases: []string{"ls"},
	Args:    cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		var (
			ifaces  []string
			actions []string
		)

		// Set interface
		if opt.Iface != "" {
			ifaces = []string{opt.Iface}
		} else {
			s, _, err := attachment.List(opt.All, opt.Page, opt.Limit)
			utils.CheckErrorAndExit(err, "Query xdp ip failed")
			for _, a := range s {
				ifaces = append(ifaces, a.Name)
			}
		}

		// Set action
		action := getOptAction()
		if action != "" {
			actions = []string{string(action)}
		} else {
			actions = []string{string(model.XDPActionPass), string(model.XDPActionRedirect)}
		}

		var (
			attachements []api.AttachmentIP
			total        int
		)
		for _, iface := range ifaces {
			for _, action := range actions {
				a, t, err := list(opt.All, opt.Page, opt.Limit, iface, action)
				utils.CheckErrorAndExit(err, "Query xdp ip failed")
				attachements = append(attachements, a...)
				total += t
			}
		}
		// TODO: add show flags
		_ = total

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
		table.Header("Name", "Action", "IP")
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
		utils.CheckErrorAndExit(err, "invalid ip")

		req := api.AddIPReq{Attachments: []api.AttachmentIP{{
			Name: opt.Iface,
			Actions: []api.XDPActionIP{{
				Action: getOptAction(),
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
		utils.CheckErrorAndExit(err, "Add xdp ip failed")
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
			AttachmentName: opt.Iface,
			Action:         getOptAction(),
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
		utils.CheckErrorAndExit(err, "Delete xdp ip failed")
	},
}

func init() {
	// list cmd
	listCmd.Flags().IntVar(&opt.Page, "page", 1, "Page number to list")
	listCmd.Flags().IntVar(&opt.Limit, "limit", 100, "Limit size per page")
	listCmd.Flags().BoolVarP(&opt.All, "all", "a", false, "List all ip")
	setFlagsAttachment(&listCmd, false)

	// add cmd
	setFlagsAttachment(&addCmd, true)

	// delete cmd
	setFlagsAttachment(&delCmd, true)
}

func setFlagsAttachment(cmd *cobra.Command, required bool) {
	cmd.Flags().StringVarP(&opt.Iface, "interface", "i", "", "XDP attachment interface")
	cmd.Flags().BoolVarP(&opt.Pass, "pass", "P", false, "XDP_PASS action")
	cmd.Flags().BoolVarP(&opt.Redirect, "redirect", "R", false, "XDP_REDIRECT action")
	if required {
		cmd.MarkFlagsOneRequired("pass", "redirect")
	}
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

func getOptAction() model.XDPAction {
	if opt.Pass {
		return model.XDPActionPass
	} else if opt.Redirect {
		return model.XDPActionRedirect
	}
	return ""
}

func list(all bool, page, limit int, iface, action string) ([]api.AttachmentIP, int, error) {
	var (
		attachements []api.AttachmentIP
		total        int
	)

	if all {
		page = 1
		limit = 100
	}
	for {
		resp, err := utils.NewHTTPRequestMessage[api.QueryIPResp](
			api.PathXDPIP,
			api.GetBodyData,
			utils.WithReqAddr(api.DefaultAPIAddr),
			utils.WithReqQuery(api.QueryPage{Page: page, Limit: limit}.ToQuery()),
			utils.WithReqQueryKV("attachment-name", iface),
			utils.WithReqQueryKV("action", action),
		)
		if err != nil {
			return nil, 0, err
		}

		for _, a := range resp.Data {
			for _, ac := range a.Actions {
				total += len(ac.IPs)
			}
		}
		attachements = append(attachements, resp.Data...)
		if total >= int(resp.Total) || !all {
			break
		}
		page++
	}
	return attachements, total, nil
}

func Export(parent *cobra.Command) {
	parent.AddCommand(ipCmd)
	setOpCommands(ipCmd)
}
