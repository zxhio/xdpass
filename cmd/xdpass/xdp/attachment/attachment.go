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
	"github.com/zxhio/xdpass/pkg/xdp"
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
			Interface:     args[0],
			Mode:          getAttachMode(),
			PullTimeout:   pullTimeout,
			Queues:        queues,
			Cores:         cores,
			ForceZeroCopy: forceZeroCopy,
			ForceCopy:     foreceNoZeroCopy,
			NoNeedWakeup:  noNeedWakeup,
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
			data = append(data, []any{
				a.Name, a.Mode, a.PullTimeout, a.Cores, a.Queues, xdp.XSKBindFlags(a.BindFlags),
			})
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
		table.Header("Name", "Mode", "Timeout", "Cores", "Queues", "Flags")
		table.Bulk(data)
		table.Render()
	},
}

var (
	// attach
	attachGeneric    bool
	attachNative     bool
	attachDriver     bool
	pullTimeout      time.Duration
	cores            []int
	queues           []int
	forceZeroCopy    bool
	foreceNoZeroCopy bool
	noNeedWakeup     bool

	// list
	listPage  int
	listLimit int
	listAll   bool
)

func getAttachMode() string {
	if attachGeneric {
		return xdp.XDPAttachModeStrGeneric
	} else if attachNative {
		return xdp.XDPAttachModeStrNative
	} else if attachDriver {
		return xdp.XDPAttachModeStrOffload
	}
	return ""
}

func init() {
	attachmentCmd.AddGroup(group)

	// attach
	attachCmd.Flags().BoolVarP(&attachGeneric, "generic", "g", false, "XDP generic(SKB) attach mode")
	attachCmd.Flags().BoolVarP(&attachNative, "native", "n", false, "XDP native attach mode")
	attachCmd.Flags().BoolVarP(&attachDriver, "offload", "o", false, "XDP offload(hardware) attach mode")
	attachCmd.Flags().DurationVarP(&pullTimeout, "timeout", "w", 0, "XDP pull timeout")
	attachCmd.Flags().IntSliceVarP(&cores, "cores", "c", []int{}, "Affinity cores")
	attachCmd.Flags().IntSliceVarP(&queues, "queues", "q", []int{}, "Interface queues")
	attachCmd.Flags().BoolVar(&forceZeroCopy, "copy", false, "Force copy")
	attachCmd.Flags().BoolVar(&foreceNoZeroCopy, "zero-copy", false, "Force zero copy")
	attachCmd.Flags().BoolVar(&noNeedWakeup, "no-need-wakeup", false, "Disable use wakeup")

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
