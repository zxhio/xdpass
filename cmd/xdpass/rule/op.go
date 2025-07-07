package rule

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/api"
	"github.com/zxhio/xdpass/internal/rule"
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
	Short:   "List rules",
	Aliases: []string{"ls"},
	Args:    cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		var mt rule.MatchType
		for _, m := range R.Matchs {
			if slices.Contains(rule.GetProtocolMatchTypes(), m.MatchType()) {
				mt = m.MatchType()
			}
		}

		queryPage := api.QueryPage{Page: listPage, Limit: listLimit}

		var rules []*rule.Rule
		if listAll {
			listPage = 1
			listLimit = 100
			total := 0
			for {
				resp, err := queryRules(queryPage, mt.String())
				utils.CheckErrorAndExit(err, "Query rules failed")

				total += len(resp.Data)
				rules = append(rules, resp.Data...)
				if total >= int(resp.Total) {
					break
				}
				listPage++
			}
		} else {
			resp, err := queryRules(queryPage, mt.String())
			utils.CheckErrorAndExit(err, "Query rules failed")
			rules = resp.Data
		}

		display(rules)
	},
}

var getCmd = cobra.Command{
	Use:   "get",
	Short: "Get rule for specified id",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ruleID, err := strconv.Atoi(args[0])
		utils.CheckErrorAndExit(err, "Check invalid rule_id")

		r, err := queryRule(ruleID)
		utils.CheckErrorAndExit(err, "Query rule failed")

		display([]*rule.Rule{r})
	},
}

var addCmd = cobra.Command{
	Use:   "add",
	Short: "Get rules",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ruleID, err := addRule(&R)
		utils.CheckErrorAndExit(err, "Add rule failed")
		utils.VerbosePrintln("Add rule success, id: %d", ruleID)
	},
}

var delCmd = cobra.Command{
	Use:     "delete",
	Short:   "Delete rule for specified id",
	Aliases: []string{"del"},
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ruleID, err := strconv.Atoi(args[0])
		utils.CheckErrorAndExit(err, "Check invalid rule_id")

		err = deleteRule(ruleID)
		utils.CheckErrorAndExit(err, "Delete rule failed")

		utils.VerbosePrintln("Delete rule success, id: %d", ruleID)
	},
}

func init() {
	listCmd.Flags().IntVar(&listPage, "page", 1, "Page number to list")
	listCmd.Flags().IntVar(&listLimit, "limit", 100, "Limit size per page")
	listCmd.Flags().BoolVarP(&listAll, "all", "a", false, "List all rules")
}

// Add can inherit different subcommands's flags.
// List can filter with different subcommands.
func setOpCommandsWithoutID(cmds ...*cobra.Command) {
	for _, cmd := range cmds {
		cmd.AddGroup(&cobra.Group{ID: "operation-without-id", Title: "Operation Commands:"})
		opCmds := []cobra.Command{addCmd, listCmd}
		for i := range opCmds {
			sub := opCmds[i]
			sub.GroupID = "operation-without-id"
			cmd.AddCommand(&sub)
		}
	}
}

// Get/Delete MUST specify rule id, NOT distinguish by subcommands.
func setOpCommands(cmds ...*cobra.Command) {
	for _, cmd := range cmds {
		cmd.AddGroup(&cobra.Group{ID: "operation", Title: "Operation Commands:"})
		opCmds := []cobra.Command{addCmd, listCmd, delCmd, getCmd}
		for i := range opCmds {
			sub := opCmds[i]
			sub.GroupID = "operation"
			cmd.AddCommand(&sub)
		}
	}
}

func getPacketMatcher(r *rule.Rule, fn func(m rule.Match) (string, bool)) string {
	for _, m := range r.Matchs {
		s, ok := fn(m)
		if ok {
			return s
		}
	}
	return "*"
}

func getLastProto(r *rule.Rule) string {
	protos := []rule.MatchType{
		rule.MatchTypeARP,
		rule.MatchTypeUDP,
		rule.MatchTypeICMP,
		rule.MatchTypeTCP,
		rule.MatchTypeHTTP,
	}

	var lastProto rule.MatchType
	for _, m := range r.Matchs {
		if slices.Contains(protos, m.MatchType()) {
			lastProto = m.MatchType()
		}
	}
	return lastProto.String()
}

func display(rules []*rule.Rule) {
	data := [][]any{}
	for _, r := range rules {
		data = append(data, []any{
			r.ID,
			strings.ToLower(getLastProto(r)),
			getPacketMatcher(r, func(m rule.Match) (string, bool) {
				switch m.MatchType() {
				case rule.MatchTypeIPv4PrefixSrc:
					return netaddr.IPv4Prefix(m.(rule.MatchIPv4PrefixSrc)).String(), true
				case rule.MatchTypeIPv4RangeSrc:
					return netaddr.IPv4Range(m.(rule.MatchIPv4RangeSrc)).String(), true
				}
				return "", false
			}),
			getPacketMatcher(r, func(m rule.Match) (string, bool) {
				switch m.MatchType() {
				case rule.MatchTypeIPv4PrefixDst:
					return netaddr.IPv4Prefix(m.(rule.MatchIPv4PrefixDst)).String(), true
				case rule.MatchTypeIPv4RangeDst:
					return netaddr.IPv4Range(m.(rule.MatchIPv4RangeDst)).String(), true
				}
				return "", false
			}),
			getPacketMatcher(r, func(m rule.Match) (string, bool) {
				switch m.MatchType() {
				case rule.MatchTypePortRangeSrc:
					return netaddr.PortRange(m.(rule.MatchPortRangeSrc)).String(), true
				case rule.MatchTypeMultiPortSrc:
					return netaddr.MultiPort(m.(rule.MatchMultiPortSrc)).String(), true
				}
				return "", false
			}),
			getPacketMatcher(r, func(m rule.Match) (string, bool) {
				switch m.MatchType() {
				case rule.MatchTypePortRangeDst:
					return netaddr.PortRange(m.(rule.MatchPortRangeDst)).String(), true
				case rule.MatchTypeMultiPortDst:
					return netaddr.MultiPort(m.(rule.MatchMultiPortDst)).String(), true
				}
				return "", false
			}),
			r.Target.TargetType().String(),
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
		tablewriter.WithRowAlignment(tw.AlignCenter),
	)
	table.Header("ID", "Proto", "Source", "Destination", "Source Ports", "Destination Ports", "Target")
	table.Bulk(data)
	table.Render()
}

func queryRules(queryPage api.QueryPage, proto string) (*api.QueryRulesResp, error) {
	return api.NewReqMessage[api.QueryRulesResp](api.APIPathQueryRules,
		api.WithReqAddr(defaultAPIAddr),
		api.WithReqQuery(fmt.Sprintf("%s&proto=%s", queryPage.ToQuery(), proto)),
	)
}

func queryRule(ruleID int) (*rule.Rule, error) {
	return api.NewReqMessage[rule.Rule](api.InstantiateRuleAPIURL(api.APIPathQueryRule, ruleID), api.WithReqAddr(defaultAPIAddr))
}

func addRule(rule *rule.Rule) (int, error) {
	data, err := json.Marshal(rule)
	if err != nil {
		return 0, err
	}
	ruleId, err := api.NewReqMessage[int](api.APIPathAddRule,
		api.WithReqAddr(defaultAPIAddr),
		api.WithReqMethod(http.MethodPost),
		api.WithReqBody(bytes.NewBuffer(data)),
	)
	if err != nil {
		return 0, err
	}
	return *ruleId, nil
}

func deleteRule(ruleID int) error {
	_, err := api.NewReqMessage[int](api.InstantiateRuleAPIURL(api.APIPathDeleteRule, ruleID),
		api.WithReqAddr(defaultAPIAddr),
		api.WithReqMethod(http.MethodDelete),
	)
	return err
}
