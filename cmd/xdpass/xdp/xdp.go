package xdp

import "github.com/spf13/cobra"

var group = cobra.Group{ID: "xdp", Title: "XDP Commands:"}

var xdpCmd = &cobra.Command{
	Use:   "xdp",
	Short: "Manage XDP program",
}

var passCmd = &cobra.Command{
	Use:     "pass",
	Short:   "Manage XDP program for XDP_PASS action",
	GroupID: group.ID,
	Aliases: []string{"p"},
}

var redirectCmd = &cobra.Command{
	Use:     "redirect",
	Short:   "Manage XDP program for XDP_REDIRECT action",
	GroupID: group.ID,
	Aliases: []string{"redir", "r"},
}

func init() {
	xdpCmd.AddGroup(&group)
}

func Export(parent *cobra.Command) {
	setOpCommands(passCmd, redirectCmd)

	parent.AddGroup(&group)
	parent.AddCommand(xdpCmd, passCmd, redirectCmd)
	xdpCmd.AddCommand(passCmd, redirectCmd)
}
