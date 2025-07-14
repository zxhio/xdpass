package ip

import (
	"github.com/spf13/cobra"
)

var (
	action string
	iface  string
)

var ipCmd = &cobra.Command{
	Use:     "ip",
	Short:   "Manage ip set for XDP program",
	Aliases: []string{"p"},
}

func init() {
	// ip
	ipCmd.PersistentFlags().StringVar(&action, "action", "redirect", "XDP action")
	ipCmd.PersistentFlags().StringVarP(&iface, "interface", "i", "", "XDP attachment interface")
}

func Export(parent *cobra.Command) {
	parent.AddCommand(ipCmd)
	setOpCommands(ipCmd)
}
