package attachment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/api"
	"github.com/zxhio/xdpass/pkg/utils"
)

var group = &cobra.Group{ID: "attachment", Title: "Attachment commands:"}

var attachmentCmd = &cobra.Command{
	Use:   "attachment",
	Short: "Manage attachment for XDP program",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var attachCmd = &cobra.Command{
	Use:     "attach",
	Short:   "Attach xdp program to interface",
	Aliases: []string{"attachment attach"},
	GroupID: group.ID,
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		req := api.AddAttachmentReq{
			Interface:   args[0],
			Mode:        attachMode,
			PullTimeout: pullTimeout,
		}
		data, err := json.Marshal(req)
		utils.CheckErrorAndExit(err, "json.Marshal")

		_, err = api.NewReqMessage[api.AddAttachmentResp](
			api.PathXDPAttachment,
			api.WithReqAddr(api.DefaultAPIAddr),
			api.WithReqMethod(http.MethodPost),
			api.WithReqBody(bytes.NewBuffer(data)),
		)
		utils.CheckErrorAndExit(err, "Add xdp attachment failed")
	},
}

var detachCmd = &cobra.Command{
	Use:     "detach",
	Short:   "Detach xdp program from interface",
	Aliases: []string{"attachment detach"},
	GroupID: group.ID,
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, err := api.NewReqMessage[api.AddAttachmentResp](
			fmt.Sprintf("%s/%s", api.PathXDPAttachment, args[0]),
			api.WithReqAddr(api.DefaultAPIAddr),
			api.WithReqMethod(http.MethodDelete),
		)
		utils.CheckErrorAndExit(err, "Add xdp attachment failed")
	},
}

var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List xdp attachment",
	Aliases: []string{"ls", "attachment list", "attachment ls"},
	GroupID: group.ID,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			attachements []api.AttachmentInfo
			total        int
		)
		if listAll {
			listPage = 1
			listLimit = 100
			for {
				resp, err := api.NewReqMessage[api.QueryAttachmentResp](
					api.PathXDPAttachment,
					api.WithReqAddr(api.DefaultAPIAddr),
					api.WithReqQuery(api.QueryPage{Page: listPage, Limit: listLimit}.ToQuery()),
				)
				utils.CheckErrorAndExit(err, "Query attachment failed")

				total += len(resp.Attachments)
				attachements = append(attachements, resp.Attachments...)
				if total >= int(resp.Total) {
					break
				}
				listPage++
			}
		} else {
			resp, err := api.NewReqMessage[api.QueryAttachmentResp](
				api.PathXDPAttachment,
				api.WithReqAddr(api.DefaultAPIAddr),
				api.WithReqQuery(api.QueryPage{Page: listPage, Limit: listLimit}.ToQuery()),
			)
			utils.CheckErrorAndExit(err, "Query attachment failed")
			attachements = resp.Attachments
		}

		data := [][]any{}
		for _, a := range attachements {
			data = append(data, []any{a.ID, a.Mode, a.PullTimeout})
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
		table.Header("ID", "Model", "Timeout")
		table.Bulk(data)
		table.Render()
	},
}

var (
	// attach
	attachMode  string
	pullTimeout time.Duration

	// list
	listPage  int
	listLimit int
	listAll   bool
)

func init() {
	attachmentCmd.AddGroup(group)

	// attach
	attachCmd.Flags().StringVarP(&attachMode, "mode", "m", "", "XDP attach mode")
	attachCmd.Flags().DurationVarP(&pullTimeout, "timeout", "w", 0, "XDP pull timeout")

	// detach

	// list
	listCmd.Flags().IntVar(&listPage, "page", 1, "Page number to list")
	listCmd.Flags().IntVar(&listLimit, "limit", 100, "Limit size per page")
	listCmd.Flags().BoolVarP(&listAll, "all", "a", false, "List all ip")
}

func Export(parent *cobra.Command) {
	parent.AddGroup(group)
	parent.AddCommand(attachmentCmd, attachCmd, detachCmd, listCmd)
	attachmentCmd.AddCommand(attachCmd, detachCmd, listCmd)
}
