package main

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/rule"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

const (
	defaultAPIAddr = "http://127.0.0.1:9921"
)

var (
	defaultClient = &client{Addr: defaultAPIAddr}
)

var (
	listPage     int
	listPageSize int
	listAll      bool
)

var listCmd = cobra.Command{
	Use:     "list",
	Short:   "List rules",
	Aliases: []string{"ls"},
	Run: func(cmd *cobra.Command, args []string) {
		var mt rule.MatchType
		for _, m := range R.Matchs {
			if slices.Contains(rule.GetProtocolMatchTypes(), m.MatchType()) {
				mt = m.MatchType()
			}
		}

		var rules []*rule.Rule
		if listAll {
			listPage = 1
			listPageSize = 100
			total := 0
			for {
				resp, err := getClient().QueryRules(listPage, listPageSize, mt.String())
				checkErrAndExit(err, "Query rules failed")

				total += len(resp.Rules)
				rules = append(rules, resp.Rules...)
				if total >= int(resp.Total) {
					break
				}
				listPage++
			}
		} else {
			resp, err := getClient().QueryRules(listPage, listPageSize, mt.String())
			checkErrAndExit(err, "Query rules failed")
			rules = resp.Rules
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
		checkErrAndExit(err, "Check invalid rule_id")

		r, err := getClient().QueryRule(ruleID)
		checkErrAndExit(err, "Query rule failed")

		display([]*rule.Rule{r})
	},
}

var addCmd = cobra.Command{
	Use:   "add",
	Short: "Get rules",
	Run: func(cmd *cobra.Command, args []string) {
		ruleID, err := getClient().AddRule(&R)
		checkErrAndExit(err, "Add rule failed")
		verbosePrintln("Add rule success, id: %d", ruleID)
	},
}

var delCmd = cobra.Command{
	Use:     "delete",
	Short:   "Delete rule for specified id",
	Aliases: []string{"del"},
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ruleID, err := strconv.Atoi(args[0])
		checkErrAndExit(err, "Check invalid rule_id")

		err = getClient().DeletePacetRule(ruleID)
		checkErrAndExit(err, "Delete rule failed")

		verbosePrintln("Delete rule success, id: %d", ruleID)
	},
}

func init() {
	listCmd.Flags().IntVar(&listPage, "page", 1, "Page number to list")
	listCmd.Flags().IntVar(&listPageSize, "page-size", 100, "Size per page")
	listCmd.Flags().BoolVarP(&listAll, "all", "a", false, "List all rules")
}

// Get/Delete MUST specify rule id, NOT distinguish by subcommands.
func setOpGetDeleteSubCommands(cmds ...*cobra.Command) {
	for _, cmd := range cmds {
		cmd.AddGroup(&cobra.Group{ID: "operation-with-id", Title: "Operation Commands:"})
		opCmds := []cobra.Command{delCmd, getCmd}
		for i := range opCmds {
			sub := opCmds[i]
			sub.GroupID = "operation"
			cmd.AddCommand(&sub)
		}
	}
}

// Add can inherit different subcommands's flags.
// List can filter with different subcommands.
func setOpAddListSubCommands(cmds ...*cobra.Command) {
	for _, cmd := range cmds {
		cmd.AddGroup(&cobra.Group{ID: "operation", Title: "Operation Commands:"})
		opCmds := []cobra.Command{addCmd, listCmd}
		for i := range opCmds {
			sub := opCmds[i]
			sub.GroupID = "operation"
			cmd.AddCommand(&sub)
		}
	}
}

func checkErrAndExit(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
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

func display(rules []*rule.Rule) {
	data := [][]any{}
	for _, r := range rules {
		data = append(data, []any{
			r.ID,
			strings.ToLower(getPacketMatcher(r, func(m rule.Match) (string, bool) {
				protos := []rule.MatchType{
					rule.MatchTypeARP,
					rule.MatchTypeTCP,
					rule.MatchTypeUDP,
					rule.MatchTypeICMP,
					rule.MatchTypeHTTP,
				}

				idx := slices.Index(protos, m.MatchType())
				if idx != -1 {
					return m.MatchType().String(), true
				}
				return "", false
			})),
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

func getClient() *client {
	envAPIAddr := os.Getenv("XDPASS_API_ADDR")
	if envAPIAddr != "" {
		return &client{Addr: envAPIAddr}
	}
	return defaultClient
}
