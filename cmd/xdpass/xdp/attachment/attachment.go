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

		_, err = utils.NewHTTPRequestMessage[api.AddAttachmentResp](
			api.PathXDPAttachment,
			api.GetBodyData,
			utils.WithReqAddr(api.DefaultAPIAddr),
			utils.WithReqMethod(http.MethodPost),
			utils.WithReqBody(bytes.NewBuffer(data)),
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
		_, err := utils.NewHTTPRequestMessage[api.AddAttachmentResp](
			fmt.Sprintf("%s/%s", api.PathXDPAttachment, args[0]),
			api.GetBodyData,
			utils.WithReqAddr(api.DefaultAPIAddr),
			utils.WithReqMethod(http.MethodDelete),
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
		attachements, _, err := List(listAll, listPage, listLimit)
		utils.CheckErrorAndExit(err, "Query attachment failed")

		data := [][]any{}
		for _, a := range attachements {
			data = append(data, []any{a.Name, a.Mode, a.PullTimeout})
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
		table.Header("Name", "Model", "Timeout")
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

func List(all bool, page, limit int) ([]api.AttachmentInfo, int, error) {
	var (
		attachements []api.AttachmentInfo
		total        int
	)

	if all {
		page = 1
		limit = 100
	}
	for {
		resp, err := utils.NewHTTPRequestMessage[api.QueryAttachmentResp](
			api.PathXDPAttachment,
			api.GetBodyData,
			utils.WithReqAddr(api.DefaultAPIAddr),
			utils.WithReqQuery(api.QueryPage{Page: page, Limit: limit}.ToQuery()),
		)
		if err != nil {
			return nil, 0, err
		}

		total += len(resp.Data)
		attachements = append(attachements, resp.Data...)
		if total >= int(resp.Total) || !all {
			break
		}
		page++
	}
	return attachements, total, nil
}
