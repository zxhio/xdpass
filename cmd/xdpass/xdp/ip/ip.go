package ip

import (
	"github.com/spf13/cobra"
)

var (
	ipAction       string
	ipAttachmentID string
)

var ipCmd = &cobra.Command{
	Use:     "ip",
	Short:   "Manage ip set for XDP program",
	Aliases: []string{"p"},
}

func init() {
	// ip
	ipCmd.PersistentFlags().StringVar(&ipAction, "action", "", "XDP action pass|redirect")
	ipCmd.PersistentFlags().StringVarP(&ipAttachmentID, "interface", "i", "", "XDP attachment interface")
}

func Export(parent *cobra.Command) {
	parent.AddCommand(ipCmd)
	setOpCommands(ipCmd)
}
