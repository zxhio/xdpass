package rule

import (
	"bytes"
	"encoding/json"
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
		rules, err := queryRules(&R, listAll, listPage, listLimit)
		utils.CheckErrorAndExit(err, "Query rules failed")
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
	Short: "Add rule",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ruleID, err := addRule(&R)
		utils.CheckErrorAndExit(err, "Add rule failed")
		utils.VerbosePrintln("rule [%d] was added successfully", ruleID)
	},
}

var delCmd = cobra.Command{
	Use:     "delete",
	Short:   "Delete by ID or rule filter (matchers and target)",
	Aliases: []string{"del"},
	Args:    cobra.RangeArgs(0, 1),
	Run: func(cmd *cobra.Command, args []string) {
		var ruleIDs []int

		if len(args) > 0 {
			ruleID, err := strconv.Atoi(args[0])
			utils.CheckErrorAndExit(err, "Check invalid rule_id")
			ruleIDs = []int{ruleID}
		} else {
			rules, err := queryRules(&R, true, 0, 0)
			utils.CheckErrorAndExit(err, "Query rules failed")
			for _, r := range rules {
				ruleIDs = append(ruleIDs, r.ID)
			}
		}

		for _, ruleID := range ruleIDs {
			err := deleteRule(ruleID)
			utils.CheckErrorAndExit(err, "Delete rule failed")
			utils.VerbosePrintln("rule [%d] was deleted successfully", ruleID)
		}
	},
}

func init() {
	listCmd.Flags().IntVar(&listPage, "page", 1, "Page number to list")
	listCmd.Flags().IntVar(&listLimit, "limit", 100, "Limit size per page")
	listCmd.Flags().BoolVarP(&listAll, "all", "a", false, "List all rules")
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

func getPacketMatcher(r *rule.Rule, fn func(m rule.Matcher) (string, bool)) string {
	for _, m := range r.Matchers {
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
	for _, m := range r.Matchers {
		if slices.Contains(protos, m.MatchType()) {
			lastProto = m.MatchType()
		}
	}
	s := lastProto.String()
	if s == "" {
		s = "*"
	}
	return s
}

func display(rules []*rule.Rule) {
	data := [][]any{}
	for _, r := range rules {
		data = append(data, []any{
			r.ID,
			r.Packets,
			r.Bytes,
			strings.ToLower(getLastProto(r)),
			getPacketMatcher(r, func(m rule.Matcher) (string, bool) {
				switch m.MatchType() {
				case rule.MatchTypeIPv4PrefixSrc:
					return m.(rule.MatchIPv4PrefixSrc).String(), true
				case rule.MatchTypeIPv4RangeSrc:
					return m.(rule.MatchIPv4RangeSrc).String(), true
				}
				return "", false
			}),
			getPacketMatcher(r, func(m rule.Matcher) (string, bool) {
				switch m.MatchType() {
				case rule.MatchTypeIPv4PrefixDst:
					return m.(rule.MatchIPv4PrefixDst).String(), true
				case rule.MatchTypeIPv4RangeDst:
					return m.(rule.MatchIPv4RangeDst).String(), true
				}
				return "", false
			}),
			getPacketMatcher(r, func(m rule.Matcher) (string, bool) {
				switch m.MatchType() {
				case rule.MatchTypePortRangeSrc:
					return m.(rule.MatchPortRangeSrc).String(), true
				case rule.MatchTypeMultiPortSrc:
					return m.(rule.MatchMultiPortSrc).String(), true
				}
				return "", false
			}),
			getPacketMatcher(r, func(m rule.Matcher) (string, bool) {
				switch m.MatchType() {
				case rule.MatchTypePortRangeDst:
					return m.(rule.MatchPortRangeDst).String(), true
				case rule.MatchTypeMultiPortDst:
					return m.(rule.MatchMultiPortDst).String(), true
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
	table.Header("ID", "Pkts", "Bytes", "Proto", "Source", "Destination", "Source Ports", "Destination Ports", "Target")
	table.Bulk(data)
	table.Render()
}

func queryRules(r *rule.Rule, all bool, page, limit int) ([]*rule.Rule, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	if all {
		page = 1
		limit = 100
	}

	rules := []*rule.Rule{}
	total := 0
	for {
		resp, err := utils.NewHTTPRequestMessage[api.QueryRulesResp](
			api.APIPathQueryRules,
			api.GetBodyData,
			utils.WithReqAddr(defaultAPIAddr),
			utils.WithReqQuery(api.QueryPage{Page: page, Limit: limit}.ToQuery()),
			utils.WithReqBody(bytes.NewBuffer(data)),
		)
		utils.CheckErrorAndExit(err, "Query rules failed")

		total += len(resp.Data)
		rules = append(rules, resp.Data...)
		if total >= int(resp.Total) || !all {
			break
		}
		page++
	}

	return rules, nil
}

func queryRule(ruleID int) (*rule.Rule, error) {
	return utils.NewHTTPRequestMessage[rule.Rule](
		api.InstantiateRuleAPIURL(api.APIPathQueryRule, ruleID),
		api.GetBodyData,
		utils.WithReqAddr(defaultAPIAddr),
	)
}

func addRule(rule *rule.Rule) (int, error) {
	data, err := json.Marshal(rule)
	if err != nil {
		return 0, err
	}
	ruleId, err := utils.NewHTTPRequestMessage[int](
		api.APIPathAddRule,
		api.GetBodyData,
		utils.WithReqAddr(defaultAPIAddr),
		utils.WithReqMethod(http.MethodPost),
		utils.WithReqBody(bytes.NewBuffer(data)),
	)
	if err != nil {
		return 0, err
	}
	return *ruleId, nil
}

func deleteRule(ruleID int) error {
	_, err := utils.NewHTTPRequestMessage[int](
		api.InstantiateRuleAPIURL(api.APIPathDeleteRule, ruleID),
		api.GetBodyData,
		utils.WithReqAddr(defaultAPIAddr),
		utils.WithReqMethod(http.MethodDelete),
	)
	return err
}
